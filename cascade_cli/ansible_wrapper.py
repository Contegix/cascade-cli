__author__ = 'sgifford'

import random
import string
import ansible
import ansible.runner
import ansible.constants
import logging

logger = logging.getLogger(__name__)

class BMAnsibleWrapper(ansible.runner.Runner):
    def __init__(self, logger, verbosity, cascade_buffer, **kwargs):
        kwargs['remote_user'] = ansible.constants.DEFAULT_REMOTE_USER
        kwargs['forks'] = ansible.constants.DEFAULT_FORKS
        
        if 'become' not in kwargs:
            kwargs['become'] = ansible.constants.DEFAULT_BECOME

        self.pattern_cache =  kwargs['pattern']

        # We want to use the same logger that is calling this class.
        self.logger = logger

        if verbosity > 0 and verbosity <= 4:
            ansible.utils.VERBOSITY = verbosity

        self.cascade_buffer = cascade_buffer
        super(BMAnsibleWrapper, self).__init__(**kwargs)

    def run(self, module_name=None, module_args=None):
        if module_name and module_args:
            self.module_name = module_name
            self.module_args = module_args
            self.pattern = self.pattern_cache
        return super(BMAnsibleWrapper, self).run()

    def run_async(self, time_limit, module_name=None, module_args=None):
        if module_name and module_args:
            self.module_name = module_name
            self.module_args = module_args
            self.pattern = self.pattern_cache
        return super(BMAnsibleWrapper, self).run_async(time_limit)

    def log(self, level, msg):
        # getLevelName also returns level value if given a name.
        self.logger.log(logging.getLevelName(level), msg)
        self.cascade_buffer.cbuffer = msg
        self.cascade_buffer.exposed_dumpbuffer()

    def loge(self, msg):
        logger.exception(msg)
        self.cascade_buffer.cbuffer = msg
        self.cascade_buffer.exposed_dumpbuffer()

    def restart(self, service):
        results = self.run(module_name='service', module_args='name=%s state=restarted' % service)
        summary = {}
        if results:
            self.__add_dark_summary(summary, results)
            for (hostname, result) in results['contacted'].items():
                if 'failed' in result:
                    summary[hostname] = {
                        'status': "Failed", 
                        'msg': "Failed to restart %s on %s because: %s" % 
                               (service, hostname, result['msg'])
                    }
                    self.log('ERROR', summary[hostname]['msg'])
                else:
                    summary[hostname] = {
                        'status': "Success", 
                        'msg': "Restarted %s on %s" % (service, hostname)
                    }
                    self.log('INFO', summary[hostname]['msg'])

        return summary

    def __add_dark_summary(self, summary, results):
        if not results['dark'] and not results['contacted']:
            raise Exception("Didn't find %s in list of hosts" % self.pattern_cache)
        for (hostname, result) in results['dark'].items():
                self.log('ERROR', "Unable to log into %s: %s" % 
                                  (self.pattern_cache, result['msg']))
                summary[hostname] = {
                    'status': "Failed", 
                    'msg': "Unable to log into server: %s" % result['msg']
                }

    def checkout(self, repo, branch, webroot, domain, confd):
        results = {}
        summary = {}

        setkey_args = {
            'module_name': 'copy',
            'module_args': "src=/etc/cascade-cli/gitlab_rsa dest=/tmp/gitlab_rsa mode=0600"
        }
        results['setkey'] = self.run(**setkey_args)
        self.__add_dark_summary(summary, results['setkey'])

        confd_args = {
            'module_name': 'file', 
            'module_args': "state=directory dest=%s/%s/conf.d" % (webroot, domain)
        }
        results['confd'] = self.run(**confd_args)

        logs_args = {
            'module_name': 'file',
            'module_args': "state=directory dest=%s/%s/logs" % (webroot, domain)
        }
        results['logs'] = self.run(**logs_args)

        # Copy drupal.inc if it exists.
        drupal_include = None
        with open('/etc/cascade-cli/drupal.inc', 'r') as f:
            drupal_include = f.read()

        if drupal_include is not None:
            drupal_inc_args = {
                'module_name': 'copy', 
                'module_args': "force=no content='%s' dest=%s/%s/drupal.inc" % 
                               (drupal_include, webroot, domain)
            }
            results['drupal_inc'] = self.run(**drupal_inc_args)

        # Copy default.conf.j2 if it exists.
        template = None
        with open('/etc/cascade-cli/default.conf.j2', 'r') as f:
            template = f.read()

        if template is not None:
            default_conf_args = {
                'module_name': 'copy', 
                'module_args': "force=no content='%s' dest=%s/%s/conf.d/%s.conf mode=0644" % 
                               (template, webroot, domain, domain)
            }
            results['default_conf'] = self.run(**default_conf_args)

        symlink_args ={
            'module_name': 'file', 
            'module_args': "state=link src=%s/%s/conf.d/%s.conf dest=%s.conf" % 
                           (webroot, domain, domain, confd)
        }
        results['symlink'] = self.run(**symlink_args)

        git_directory = "%s/%s/htdocs" % (webroot, domain)
        git_args = {
            'module_name': 'git', 
            'module_args': "repo=%s dest=%s version=%s key_file=/tmp/gitlab_rsa force=no ssh_opts='-o StrictHostKeyChecking=no'" % 
                           (repo, git_directory, branch)
        }
        results['git'] = self.run(**git_args)

        for (hostname, result) in results['git']['contacted'].items():
            if 'stderr' in result:
                summary[hostname] = {
                    'status': "Failed",
                    'msg': "%s failed to checkout because: %s" % 
                           (hostname,result['stderr'].strip()) 
                }
                self.log('ERROR', summary[hostname]['msg'])
            elif 'failed' in result:
                summary[hostname] = {
                    'status': "Failed",
                    'msg': "Possible missing branch %s because %s failed with: %s" % 
                           (branch, hostname, result['msg'])
                }
                self.log('ERROR', summary[hostname]['msg'])
            elif 'changed' in result and result['changed'] == False:
                summary[hostname] = {
                    'status': "Success",
                    'msg': "%s:%s is already up to date with branch %s in %s" % 
                           (hostname, git_directory, branch, repo)
                }
                self.log('INFO', summary[hostname]['msg'])
            elif 'changed' in result and result['changed'] == True:
                summary[hostname] = {
                    'status': "Success",
                    'msg': "Deployed branch %s in %s to %s:%s" % 
                           (branch, repo, hostname,git_directory)
                }
                self.log('INFO', summary[hostname]['msg'])
            else:
                self.log('CRITICAL', result)

        removekey_args = {
            'module_name': 'file', 
            'module_args': "path=/tmp/gitlab_rsa state=absent"
        }
        results['removekey'] = self.run(**removekey_args)

        # TODO: Do we want to remove the .git subdirectory on non-dev machines 
        # to prevent committing there?
        return summary

    def _create_backup(self, database):
        results={}
        summary={}
        results['create'] = self.run(module_name='mysql_db', module_args='name=%s state=present' % (database))

        self.__add_dark_summary(summary, results['create'])

        for (hostname, result) in results['create']['contacted'].items():
            if 'stderr' in result:
                summary[hostname] = {
                    'status': "Failed",
                    'msg': "%s failed because: %s" % 
                           (hostname,result['stderr'].strip()) 
                }
                self.log('CRITICAL', summary[hostname]['msg'])
            elif 'failed' in result:
                summary[hostname] = {
                    'status': "Failed",
                    'msg': "Mysql service off? %s failed with: %s" % 
                           (hostname, result['msg'])
                }
                self.log('CRITICAL', summary[hostname]['msg'])
            elif 'changed' in result and result['changed'] == False:
                summary[hostname] = {
                    'status': "Success",
                    'msg': "Found %s on %s" % (database, hostname)
                }
                self.log('INFO', summary[hostname]['msg'])
            elif 'changed' in result and result['changed'] == True:
                summary[hostname] = {
                    'status': 'Success',
                    'msg': "Created %s on %s" % (database, hostname)
                }
                self.log('INFO', summary[hostname]['msg'])
            else:
                self.log('CRITICAL', result)

        if results['create']['contacted'].items():
            results['date'] = self.run(module_name='command', module_args="date '+%G/%m/%d/%H-%M-%S'")
            backup_path = ""
            for (hostname, result) in results['date']['contacted'].items():
                backup_path = "/opt/backup/mysql/%s/%s" %(result['stdout'],database)
            results['mkdir'] = self.run(module_name='file', module_args="path=%s state=directory" % backup_path)
            backup_file = "%s/%s.sql.gz" % (backup_path, database)

            self.log('WARNING', "Please be patient: backing up to %s" % backup_file)

            #TODO: MAKE 8 hours a config var
            backup_init_args = {
                'time_limit': 28800,
                'module_name': 'mysql_db',
                'module_args': 'name=%s state=dump target=%s' % (database, backup_file)
            }
            results['backup_init'], poller = self.run_async(**backup_init_args)
            results['backup'] = poller.wait(28800, 5)

            for (hostname, result) in results['backup']['contacted'].items():
                if 'stderr' in result:
                    summary[hostname] = {
                        'status': "Failed",
                        'msg': "%s failed to backup %s to %s because: %s" % 
                               (hostname, database, backup_file, result['stderr'].strip())
                    }
                    self.log('CRITICAL', summary[hostname]['msg'])
                    return False
                elif 'failed' in result:
                    summary[hostname] = {
                        'status': "Failed",
                        'msg': "%s failed because %s" % (hostname, result['msg'])
                    }
                    self.log('CRITICAL', summary[hostname]['msg'])
                elif 'changed' in result and result['changed'] == False:
                    summary[hostname] = {
                        'status': "Failed",
                        'msg': "%s failed because " % (hostname, result['msg'])
                    }
                    self.log('CRITICAL', summary[hostname]['msg'])
                elif 'changed' in result and result['changed'] == True:
                    summary[hostname] = {
                        'status': "Success",
                        'msg': "Backed up %s on %s to %s" % (database, hostname, backup_file)
                    }
                    self.log('INFO', summary[hostname]['msg'])
                else:
                    self.log('CRITICAL', result)

            return backup_file
        return False

    def __get_port(self, host):
        temp_vars = self.inventory.get_variables(host, vault_password=self.vault_pass)
        hostvars = ansible.runner.HostVars(temp_vars, self.inventory, vault_password=self.vault_pass)
        port = hostvars.get('ansible_ssh_port', self.remote_port)
        if port is None:
            port = ansible.constants.DEFAULT_REMOTE_PORT
        return port

    def _transfer_file(self, source_asset, other_machine, dest_asset, pull=False, relative=True):
        results={}
        summary={}

        if relative:
            relative = "R"
        else:
            relative = ""

        other_machine = other_machine if other_machine else self.pattern_cache
        source_machine = destination_machine = self.pattern_cache

        if pull:
            source_machine = other_machine
        else:
            destination_machine = other_machine

        self.log('WARNING', "Please be patient: copying %s:%s to %s:%s." % (source_machine, source_asset, destination_machine, dest_asset))
        port = self.__get_port(destination_machine)

        poller = None

        if source_machine is not destination_machine:
             if pull:
                 results['rsync_init'], poller = self.run_async(28800,module_name='shell', module_args='rsync -avC%s --temp-dir=/tmp --exclude-from=$(/bin/ls %s.rsyncignore 2>/dev/null) -e "ssh -o StrictHostKeyChecking=no -p %s -i /root/.ssh/id_rsa" cascade_admin@%s:%s %s'%(relative, dest_asset, port, source_machine, source_asset, dest_asset))
             else:
                 results['rsync_init'], poller = self.run_async(28800,module_name='shell', module_args='rsync -avC%s --temp-dir=/tmp --exclude-from=$(/bin/ls %s.rsyncignore 2>/dev/null) %s -e "ssh -o StrictHostKeyChecking=no -p %s -i /root/.ssh/id_rsa" cascade_admin@%s:%s'%(relative, dest_asset, source_asset, port, destination_machine, dest_asset))
        else:
             if pull:
                 results['rsync_init'], poller = self.run_async(28800,module_name='shell', module_args='rsync -avC%s --temp-dir=/tmp --exclude-from=$(/bin/ls %s.rsyncignore 2>/dev/null) %s %s'%(relative, dest_asset, source_asset, dest_asset))
             else:
                 results['rsync_init'], poller = self.run_async(28800,module_name='shell', module_args='rsync -avC%s --temp-dir=/tmp --exclude-from=$(/bin/ls %s.rsyncignore 2>/dev/null) %s %s'%(relative, source_asset, source_asset, dest_asset))

        results['rsync'] = poller.wait(28800, 5)

        for (hostname, result) in results['rsync']['contacted'].items():
            if 'stderr' in result and result['stderr'].strip():
                summary[hostname] = {
                    'status': 'Failed',
                    'msg': "%s failed to copy %s to %s:%s because: %s" % 
                           (source_machine, source_asset, destination_machine, 
                            dest_asset, result['stderr'].strip())
                }
                self.log('CRITICAL', summary[hostname]['msg'])
                return False
            elif 'failed' in result:
                summary[hostname] = {
                    'status': 'Failed',
                    'msg': "%s failed to copy %s to %s:%s because: %s" % 
                           (source_machine, source_asset, destination_machine, 
                            dest_asset, result['msg'])
                }
                self.log('CRITICAL', summary[hostname]['msg'])
                return False
            elif 'changed' in result and result['changed'] == False:
                summary[hostname] = {
                    'status': 'Failed',
                    'msg': "%s failed to copy %s to %s:%s because: %s" % 
                           (source_machine, source_asset, destination_machine,
                            dest_asset, result['msg']) 
                }
                self.log('CRITICAL', summary[hostname]['msg'])
                return False
            elif 'changed' in result and result['changed'] == True:
                summary[hostname] = {
                    'status': 'Success',
                    'msg': "Copied %s:%s to %s:%s" % 
                           (source_machine, source_asset, destination_machine, dest_asset)
                }
                self.log('INFO', summary[hostname]['msg'])
            else:
                self.log('CRITICAL', result)
                return False

        return summary

    def _import_backup(self, source_db, dest_database):
        results = {}
        summary={}
        self.log('WARNING', "Please be patient: importing %s into %s on %s." % 
                            (source_db, dest_database, self.pattern_cache))


        results['drop'] = self.run(module_name='mysql_db', module_args='name=%s state=absent' % (dest_database))
        results['create'] = self.run(module_name='mysql_db', module_args='name=%s state=present' % (dest_database))

        results['import_init'], poller = self.run_async(28800, module_name='mysql_db', module_args="name=%s state=import target=%s" % (dest_database, source_db))
        results['import'] = poller.wait(28800,5)
        for (hostname, result) in results['import']['contacted'].items():
            if 'stderr' in result and result['stderr'].strip():
                summary[hostname] = {
                    'status': 'Failed',
                    'msg': "%s failed to import %s to %s because: %s" % 
                           (hostname, source_db, dest_database, result['stderr'].strip())
                }
                self.log('CRITICAL', summary[hostname]['msg'])
                return False
            elif 'failed' in result:
                summary[hostname] = {
                    'status': 'Failed',
                    'msg': "%s failed to import %s to %s because: %s" % 
                           (hostname, source_db, dest_database, result['msg'])
                }
                self.log('CRITICAL', summary[hostname]['msg'])
                return False
            elif 'changed' in result and result['changed'] == False:
                summary[hostname] = {
                    'status': 'Failed',
                    'msg': "%s failed to import %s to %s because: %s" % 
                           (hostname, source_db, dest_database, result['msg'])
                }
                self.log('CRITICAL', summary[hostname]['msg'])
                return False
            elif 'changed' in result and result['changed'] == True:
                summary[hostname] = {
                    'status': 'Success',
                    'msg': "Imported %s to %s on %s" % 
                           (source_db, dest_database, hostname)
                }
                self.log('INFO', summary[hostname]['msg'])
            else:
                self.log('CRITICAL', result)
                return False

        results['delete'] = self.run(module_name='file', 
                                     module_args="path=/tmp/opt state=absent")
        return summary

    def generate_password(self, length=18):
        pass_criteria = string.ascii_uppercase + string.digits + string.ascii_lowercase
        return ''.join(random.choice(pass_criteria) for i in range(length))

    def create_database(self, db_name, db_user=None, db_pass=None):
        if not db_name:
            return False

        results = {}
        if not db_user:
            db_user = db_name
        if not db_pass:
            db_pass = self.generate_password()

        # MySQL has a 16 character limit on user names.
        db_user = (db_user[:16]) if len(db_user) > 16 else db_user

        try:
            results['create'] = self.run(module_name='mysql_db', module_args='name=%s state=present' % db_name)
            results['create_user'] = self.run(module_name='mysql_user', module_args='name=%s password=%s priv=%s.*:ALL state=present' % (db_user, db_pass, db_name))

            self.log('INFO', 
                     "'%s' has been created on '%s' with user '%s' and password '%s'." % 
                     (db_name, self.pattern, db_user, db_pass))
        except Exception, e:
            self.log('ERROR', e)

        return results

    def push_database_settings(self, dest_path, source_path, filename):
        db_settings_file = None
        with open('%s/%s' % (source_path, filename), 'r') as f:
            db_settings_file = f.read()

        if db_settings_file is not None:
            db_settings_args = {
                'module_name': 'copy',
                'module_args': "force=no content='%s' dest=%s/%s" % 
                               (db_settings_file, dest_path, filename)
            }
            return { 'db_settings': self.run(**db_settings_args) }
        
        self.log('ERROR', "Missing DB settings file.")
        return False

    def git_add_origin(self, docroot, origin):
        results = { 'add_origin': '' }
        results['add_origin'] = self.run(module_name='shell', module_args='git init;git remote rename origin upstream;git remote add origin %s chdir=%s' % (origin, docroot))
        #We can probably ignore any results
        #however, the following three lines are not errors due
        #to the fact we're running three commands in one
        #Reinitialized existing Git repository in docroot
        #fatal: remote upstream already exists
        #fatal: remote origin already exists

    def find_symlinks(self, docroot):
        results = {
            'symlinks': '',
            'symlink_destinations': '',
        }
        symlinks = {}
        results['symlinks'] = self.run(module_name='shell', module_args='find %s -mount -maxdepth 7 -type l' % docroot)
        self.module_vars['items_lookup_plugin'] = "items"
        if 'stdout' in results['symlinks']['contacted'][self.pattern]:
            self.module_vars['items_lookup_terms'] = results['symlinks']['contacted'][self.pattern]['stdout'].split("\n")
            results['symlink_destinations'] = self.run(module_name='shell', module_args='readlink -f {{ item }} | grep -v %s' % docroot)
     
        try:
            for result in results['symlink_destinations']['contacted'][self.pattern]['results']:
                if result:
                	symlinks[result['item'].replace("%s/" % docroot,"")] = result['stdout']
        except Exception as e:
            self.loge(e.message)
        return symlinks

    def find_known_ignored(self, docroot, known_ignored):
        results = { 'found_ignored': '' }
        if known_ignored:
            self.module_vars['items_lookup_plugin'] = "items"
            self.module_vars['items_lookup_terms'] = known_ignored

            try:
                results['found_ignored'] = self.run(module_name='shell', module_args="find . -wholename '{{ item }}' -printf '%%P\n' 2>/dev/null chdir=%s" % docroot)
            except Exception as e:
                self.loge(e.message)
        
	    paths = {}
            try:
                for result in results['found_ignored']['contacted'][self.pattern]['results']:
	             if result['stdout']:
		         for line in result['stdout'].split("\n"):		      
            	             paths[line] = result['item']
            except Exception as e:
                self.loge(e.message)
            return paths

        return False

    def git_ignore_add(self, docroot, ignore_list):
        results = { 'git_ignore': '' }
        if ignore_list:
            self.module_vars['items_lookup_plugin'] = "items"
            self.module_vars['items_lookup_terms'] = ignore_list
            results['git_ignore'] = self.run(module_name='shell', module_args='git rm --cached -r {{ item }} &>/dev/null;grep -q -F "{{ item }}" .gitignore || echo "{{ item }}" >> .gitignore chdir=%s' % docroot)
        #I DON'T KNOW IF THERE'S ANYTHING WE NEED TO DO HERE

    def git_commit_push(self, docroot):
        results = { 'add_origin': '' }
        try:
            results['add_origin'] = self.run(module_name='shell', module_args='git add -A 1>/dev/null;git commit -m"Automated Cascade Import Commit" 1>/dev/null;git push --all origin;git push --tags origin chdir=%s' % (docroot))
        except Exception as e:
            self.loge(e.message)
        #TODO: Do some testing on the output. Return true/false

