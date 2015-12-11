import logging
import collections
import os
from datetime import datetime
from pytz import timezone

import yaml
from yaml.representer import SafeRepresenter

import ConfigParser

from prettytable import PrettyTable

from giturlparse import parse as gitparse

from ansible_wrapper import BMAnsibleWrapper
import gitlab_extras

logger = logging.getLogger('root')

################
#For debugging
###############
import traceback
def exit_on_exception(func):
   def func_wrapper(*args, **kwargs):
       try:
            return func(*args, **kwargs)
       except Exception as e:
            print e
            print traceback.format_exc()
            exit()
   return func_wrapper

######Make YAML Orderings keep the order###
def dict_representer(dumper, data):
    return dumper.represent_dict(data.iteritems())

def dict_constructor(loader, node):
    return collections.OrderedDict(loader.construct_pairs(node))

yaml.add_representer(collections.OrderedDict, dict_representer)
yaml.add_representer(str, SafeRepresenter.represent_str)
yaml.add_representer(unicode, SafeRepresenter.represent_unicode)
yaml.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, dict_constructor)

class CascadeConfig(object):
    def __init__(self, path, cascade_buffer, verbosity=0):
        self.results = {}
        self.settings_path = path
        self.cascade_buffer = cascade_buffer
        self.verbosity = verbosity
        self.git = None
        self.site_types = [
            'Drupal 6', 
            'Drupal 7', 
            'Drupal 8', 
            'Wordpress 3', 
            'Wordpress 4', 
            'Wordpress 5', 
            'Magento', 
            'Other'
        ]
        self.required = [
            ('roles', []),
            ('inventory', []),
            ('machines', {}),
            ('environments', {}),
            ('backdoor', [])
        ]

        try:
            with open(self.settings_path, 'r+') as f:
                self.settings = yaml.load(f)

            if self.settings is None:
                self.settings = {}

            # Setup the nodes required for Cascade to work.
            for key, structure in self.required:
                if key not in self.settings or self.settings[key] is None:
                    self.settings[key] = structure
                setattr(self, key, self.settings[key])

            if 'deployhook' not in self.settings or not self.settings['deployhook']:
                self.settings['deployhook'] = { 'url': 'http://localhost' }
                self.log('WARNING', "Setting a default deployhook URL. This must be " \
                                    "properly set in order for deploy hooks to work.")
        except Exception as e:
            self.loge("Failed to initialize CascadeConfig")
            exit(1)

        try:
            self.git_url = self.settings['gitlab']['url']
            self.git_key = self.settings['gitlab']['api_key']
            self.git = gitlab_extras.GitlabWrapper(self.git_url, token=self.git_key)
        except Exception as e:
            self.loge("Failed to initialize Git connection")

    def set_verbosity(self, verbosity=0):
        self.verbosity = verbosity

    def get_verbosity(self):
        return self.verbosity

    def save(self, restart=True):
        logger.debug('Saving %s' % self.settings_path)
        with open(self.settings_path, 'w') as settings_file:
            settings_file.write(yaml.dump(self.settings, allow_unicode=False, default_flow_style=False))
        if (restart):
            os.system("/sbin/service cascade restart 2%1>/dev/null")

    def clear_backdoor_user(self):
        while len(self.backdoor):
            self.backdoor.pop()

        self.save(False)

    def save_backdoor_user(self, username, password):
        username = self.sanitize(username)
        password = self.sanitize(password)

        if not any([backdoor for backdoor
                    in self.backdoor
                    if backdoor['username']
            and role['username'] == username]):
            self.backdoor.append({
                "username": username,
                "password": password
            })

            self.save()
            self.log('INFO', "backdoor %s / %s added to %s" % (username, password, self.settings_path))
            return True
        else:
            self.log('WARNING', "backdoor %s already exists in %s" % (username, self.setting_path))
        return False

    def sanitize(self, string, spacer=None):
        if not isinstance(string, str) and not isinstance(string, unicode):
            return string
        if not string:
            return ''
        
        # Remove any trailing whitespace
        string = string.strip()

        if spacer == True:
           spacer = '_'

        if spacer:
            string = string.lower().replace(' ', spacer)

        return string

    def log(self, level, msg):
        # getLevelName also returns level value if given a name.
        # TODO: evaluate to see if logger should be in CascadeConfig.. probably
        logger.log(logging.getLevelName(level), msg)
        self.cascade_buffer.cbuffer = msg
        self.cascade_buffer.exposed_dumpbuffer()

    def loge(self, msg):
        logger.exception(msg)
        self.cascade_buffer.cbuffer = msg
        self.cascade_buffer.exposed_dumpbuffer()

    def roles_list(self):
        logger.debug('Creating roles table from %s' % self.settings_path)
        table = PrettyTable(['Title', 'Machine Name'])
        table.align = 'l'
        table.padding_width = 1
        result = ''

        if not self.roles_exist():
            logger.debug('No roles found')
            result += 'No roles exist!\nExample Roles Table:'
            table.add_row(['Administrator (example)', 'admin (example)'])
        else:
            logger.debug('Roles found, populating table...')
            result += 'Current roles:'
            for role in self.roles:
                table.add_row([role['name'], role['key']])

        return result + '\n' + table.get_string()

    def roles_add(self, title):
        machine_name = self.sanitize(title, True)
        title = self.sanitize(title)

        if not any([role for role 
                    in self.roles
                    if role['key'] 
                        and role['key'] == machine_name]):
            self.roles.append({
                "key": machine_name,
                "name": title
            })
            
            self.save()
            self.log('INFO', "role %s added" % machine_name)
            return True
        else:
            self.log('WARNING', "role %s already exists" % machine_name)
        return False

    def role_exist(self, machine_name):
        machine_name = self.sanitize(machine_name, True)
        matching_roles = [r for r in self.roles if r['key'] == machine_name]
        if matching_roles:
            return matching_roles[0]
        return None

    def roles_exist(self):
        return self.roles and len(self.roles) > 0

    def roles_delete(self, machine_name):
        machine_name = self.sanitize(machine_name, True)
        logger.debug('Attempting to delete role %s' % machine_name)
        with_role_len = len(self.roles)
        self.roles[:] = [role for role in self.roles if role['key'] != machine_name]
        self.save()
        if with_role_len > len(self.roles):
            self.log('INFO', "Role successfully deleted")
            return True
        self.log('WARNING', "No roles deleted")
        return False

    def envs_exist(self):
        return self.environments and len(self.environments) > 0

    def envs_list(self):
        table = PrettyTable(['Machine Name', 'Title', 'VCS Machines', 'DB Machines'])
        table.align = 'l'
        table.padding_width = 1
        table.hrules = True
        result = ''

        if self.envs_exist():
            result += 'Current Environments:\n'
            try:
                for env in self.environments.items():
                    (machine_name, details) = env
                    title = machine_name

                    if 'title' in details:
                        title = details['title']

                    # Format git machines into something readable
                    vcs_machines = ''
                    if 'vcs_machines' in details:
                        for idx, m in enumerate(details['vcs_machines']):
                            vcs_machines += '%s (%s)' % (m['machine'], m['webroot'])
                            if (idx + 1) < len(details['vcs_machines']):
                                vcs_machines += '\n'

                    # Now the db machines
                    db_machines = ''
                    if 'db_machines' in details:
                        for idx, m in enumerate(details['db_machines']):
                            if 'machine' in m:
                                db_machines += '%s' % (m['machine'])

                            #if 'prefix' in m:
                            #    db_machines += ', Prefix: %s' % m['prefix']
                            if (idx + 1) < len(details['db_machines']):
                                db_machines += '\n'

                    table.add_row([machine_name, title, vcs_machines, db_machines])
            except Exception as e:
                self.loge("Failed to build machine list")
        else:
            result += 'No environments exist! Example Environment List:\n'
            table.add_row([
                'dev (example)', 
                'Development (example)', 
                'devserver (example)', 
                'devserver (example)'
            ])

        return result + '\n' + table.get_string()
        
    def envs_add(self, name, title):
        name = self.sanitize(name, True)
        title = self.sanitize(title)

        if name not in self.environments:
            self.environments[name] = { "title": title }
        else:
            self.environments[name]['title'] = title;
            self.log('WARNING', "Environment %s is being overwritten from %s" % (name, self.environments[name]['title']))

        self.save()
        self.log('INFO', "Environment %s added/updated" % name)

    def envs_edit_title(self, env_to_edit, new_title=None):
        env_to_edit = self.sanitize(env_to_edit, True)
        env = self.environments[env_to_edit]

        if new_title:
            # 'name' in settings.yml is really the title
            env['title'] = self.sanitize(new_title)
            self.save() 

    def env_in_use(self, env):
        logger.debug("Checking if '%s' is in use (has code deployments)" % env)
        for group in self.inventory:
            if 'websites' in group:
                for site in group['websites']:
                    if 'environments' in site:
                        for e in site['environments']:
                            if env == e:
                                return True
        return False

    def envs_delete(self, env):
        self.log('INFO', "Attempting to delete env '%s'" % env)
        
        if self.env_in_use(env):
            self.log('INFO', "Failed to delete '%s', sites contain code deployments to or from this environment." % env)
            return False

        with_env_len = len(self.environments)
        del self.environments[env]
        self.save()
        
        if with_env_len > len(self.environments):
            self.log('INFO', "Environment successfully deleted")
            return True
        self.log('WARNING', "No environments deleted")
        return False

    def envs_databases(self, env):
        table = PrettyTable(['Machine', 'Prefix'])
        table.align = 'l'
        table.padding_width = 1

        def _list_dbs(e, t):
            if 'db_machines' in self.environments[e]:
                for db_machine in self.environments[e]['db_machines']:
                    prefix = ''
                    if 'prefix' in db_machine:
                        prefix = db_machine['prefix']
                    t.add_row([db_machine['machine'], prefix])

        if env:
            table_title = 'Databases for environment %s:' % env
            _list_dbs(env, table)
        else:
            table_title = 'All databases:'
            [_list_dbs(e, table) for e in self.environments]
            
        return table_title + '\n' + table.get_string()

    def services_list(self, machines=None):
        try:
            if not machines:
                machines = self.machines
            elif not isinstance(machines, list):
                machines = machines.split(',')
        except Exception as e:
            self.loge("Failed to list machines")
            return

        table = PrettyTable(['Machine', 'Services'])
        table.align = 'l'
        table.padding_width = 1
        result = 'Services:'

        for machine in machines:
            machine = machine.strip()
            services = ''

            if 'services' in self.machines[machine]:
                itr = iter(self.machines[machine]['services'])
                for idx, service in enumerate(self.machines[machine]['services']):
                    services += service['name']
                    if (idx + 1) < len(self.machines[machine]['services']):
                        services += ',\n'

            table.add_row([machine, services])

        return result + '\n' + table.get_string()

    def services_add(self, machine, service):
        machine = self.sanitize(machine, True)
        if machine not in self.machines:
            self.log('ERROR', "Machine %s not found" % machine)
        else:
            if 'services' not in self.machines[machine]:
                self.machines[machine]['services'] = []

            if not any([s for s in self.machines[machine]['services'] if s['name'] and s['name'] == service]):
                self.machines[machine]['services'].append({
                    'name': service
                })
                self.save()
                self.log('INFO', "Service %s added to machine %s" % (service, machine))
            else:
                self.log('WARNING', "Service %s already exists on machine %s" % (service, machine))

    def services_delete(self, service_bin, machine):
        machine = self.sanitize(machine, True)
        if machine not in self.machines:
            self.log('ERROR', "Machine %s not found" % machine)
        else:
            if 'services' not in self.machines[machine]:
                self.log('WARNING', "Machine has no services")
                return False

            index = None
            for idx, service in enumerate(self.machines[machine]['services']):
                if service['name'] == service_bin:
                    index = idx
                    break

            if index is not None:
                del self.machines[machine]['services'][index]
                self.save()
                self.log('INFO', "Service %s removed from machine %s" % (service_bin, machine))

    def group_path_exists(self, path):
        path = self.sanitize(path).lower()

        for idx, existing_group in enumerate(self.inventory):
            if existing_group['group'] and existing_group['group'].lower() == path:
                return True
        else:
            self.log('ERROR', "Group %s does not exist in %s" % (path, self.settings_path))

        return False

    def group_exists(self, name):
        for g in self.inventory:
            if 'group' in g and g['group'] == name:
                return True
        return False

    def groups_exist(self):
        return self.inventory and len(self.inventory) > 0

    def groups_list(self):
        table = PrettyTable(['Name'])
        table.align = 'l'
        table.padding_width = 1
        result = ''

        if not self.inventory:
            result += 'No groups currently exist!\nCascade Groups (Example)'
            table.add_row(['NEWS (example)'])
        else:
            result += 'Cascade Groups'
            for g in self.inventory:
                if 'group' in g: 
                    table.add_row([g['group']])
            
        return result + '\n' + table.get_string()

    def groups_add(self, name, notes=None):
        # First check if the group exists in Gitlab. We find a group by its 
        # path but are given a name so we sanitize appropriately...
        path = self.sanitize(name, True)
        
        group = self.git.findgroup(path)
        if not group:
            group = self.git.creategroup(name, path)

            if 'id' in group:
                self.log('INFO', "Group '%s' added in gitlab with id %s" % (name, group['id']))
            else:
                # We need the group to exist in Gitlab so return if this fails.
                self.log('ERROR', "Group '%s' failed to create in gitlab" % name)
                return False
        else:
            logger.debug("Group '%s' already exists in Gitlab" % name)

        # Add users if the group already exists. The API method is idempotent.
        for gituser in self.git.getusers():
            if gituser['is_admin']:
                newmember = self.git.addgroupmember(group['id'], gituser['id'], "owner")
                if newmember:
                    self.log('INFO', "%s added as group owner of '%s'" % (gituser['username'], name))
                    os.system("/sbin/service cascade restart 2%1>/dev/null")

        # If the group doesn't exist in Cascade then add it.
        if not any([g for g in self.inventory if g['group'] and g['group'] == name]):
            new_group = {
                "group": name,
                "websites": []
            }

            if notes is not None:
                new_group['notes'] = notes

            self.inventory.append(new_group)
            self.save()
            self.log('INFO', "Group '%s' added" % name)
        else:
            self.log('WARNING', "Group '%s' already exists" % name)

        return True

    def groups_edit_notes(self, name, notes):
        self.log('INFO', "Attempting to edit group '%s'" % name)
        if not any([name, notes]):
            return False

        for gidx, group in enumerate(self.inventory):
            if group['group'] == name:
                group['notes'] = notes
                break

        self.log('INFO', "Updated notes")
        self.save()

    def groups_delete(self, name):
        self.log('INFO', "Attempting to delete group '%s'" % name)

        group_index = 0
        for gidx, group in enumerate(self.inventory):
            if group['group'] == name:
                group_index = gidx
                break
        
        if self.inventory[group_index]['websites']:
            self.log('WARNING', "Attempting to delete group with sites")
            return False
        
        with_group_len = len(self.inventory)
        del self.inventory[group_index]
        self.save()

        git_group = self.git.findgroup(self.sanitize(name, True))
        if git_group and 'id' in git_group:
        
            git_group = self.git.getgroups(git_group['id'])
            if len(git_group['projects']):
                self.log('WARNING', "Leaving gitlab group because it is not empty")
            elif self.git.deletegroup(git_group['id']):
                self.log('WARNING', "Group successfully deleted from Gitlab")

        if with_group_len > len(self.inventory):
            self.log('INFO', "Group successfully deleted from Cascade")
            return True
        self.log('WARNING', "No groups deleted")
        return False

    def site_exists(self, domain):
        for group in self.inventory:
            if 'websites' in group:
                for site in group['websites']:
                    if site['domain'] == domain:
                        return True
        return False

    def sites_exist(self):
        for group in self.inventory:
            if 'websites' in group:
                for site in group['websites']:
                    if site['domain']:
                        return True
        return False

    def sites_list(self, group=None):
        table = PrettyTable([
            'Group', 
            'Domain (type)', 
            'Repository', 
            'Deployments',
        ])
        table.align = 'l'
        table.padding_width = 1
        table.max_width["Repository"] = 20
        result = ''

        def _add_rows(group, table):
            if 'websites' in group:
                for idx, site in enumerate(group['websites']):
                    vcs_deploys = []
                    db_deploys = []
                    asset_syncs = []

                    if 'environments' in site:
                        for env in site['environments'].items():
                            (key, details) = env
                            if 'vcs' in details:
                                for vcs in details['vcs']:
                                    vcs_deploys.append("Branch '%s' to env '%s'" % (vcs['branch'], key)) 
                            if 'db' in details:
                                for db in details['db']:
                                    db_deploys.append("Database '%s' to env '%s'" % (db['name'], key)) 
                            if 'assets' in details:
                                for assets in details['assets']:
                                    asset_syncs.append("Asset '%s' synced to env '%s'" % (assets['title'], key)) 
                                
                    table.add_row([
                            group['group'], # Group
                            "%s (%s)" % (site['domain'], site['type']), # Domain
                            site['repo'], # Repo
                            "%s\n%s\n%s" % (',\n'.join(vcs_deploys), ',\n'.join(db_deploys), ',\n'.join(asset_syncs)), # Deployments
                        ])
        
        if group:
            [_add_rows(g, table) for g in self.inventory if group == g['group']]
        else:
            [_add_rows(g, table) for g in self.inventory]
       
        if len(table._rows) > 0:
            result += 'Current Sites:'
        else:
            table.add_row([
                'news (example)', 
                'example.com (Drupal 7) (example)',
                'git@... (example)',
                "Branch 'bmesh_dev' to env 'dev' (example)\n" \
                "Database 'd7_dev' to env 'dev' (example)\n" \
                "Asset 'sites/default/files' to env 'dev' (example)"
            ])

            result += 'No sites exist!\nExample Sites List:'

        return result + '\n' + table.get_string()

    def find_group_index(self, group_path):
        """ Gets the Group index from the path. """
        group_path = self.sanitize(group_path, True)

        for index, group in enumerate(self.inventory):
            if group['group'] and group['group'].lower() == group_path:
                return index
        else:
            self.log('ERROR', "Group %s does not exist in %s" % (group_path, self.settings_path))

        return None

    def sites_add(self, domain, group_path, site_type, project_path=None, notes=None):
        group_path = self.sanitize(group_path, True)
        group = self.git.findgroup(group_path)

        if group:
            domain = self.sanitize(domain, True)

            if notes is not None:
                notes = self.sanitize(notes)

            group_index = self.find_group_index(group_path)
            if not self.inventory[group_index]['websites']:
                self.log('INFO', "Missing websites for group %s. Setting empty array." % group_index)
                self.inventory[group_index]['websites'] = []

            search_project = domain.replace(".", "-")
            if project_path:
                search_project = project_path

            project = self.git.findproject(search_project, group['path'])

            if project:
                self.log('WARNING', "Found project %s in git already" % domain)
            else:
                self.log('INFO', "Adding project %s to gitlab" % domain)
                create_args = {
                    'namespace_id': group['id'],
                    'merge_request_enabled': True,
                }

                if notes:
                    create_args['description'] = notes
                if project_path:
                    create_args['path'] = project_path

                project = self.git.createproject(domain.replace(".", "-"),
                                                 **create_args)

            if not project:
                self.log('WARNING', "Unable to create project %s/%s in gitlab." % (group['path'], domain))
            else:
                hooks = self.git.getprojecthooks(project['id'])
                if 'deployhook' in self.settings:
                    for hook in hooks:
                        if hook['url'] == self.settings['deployhook']['url']:
                            break
                    else:
                        self.git.addprojecthook(project['id'], self.settings['deployhook']['url'], push=True, merge_requests=True)
                else:
                    self.log('ERROR', "Unable to add Gitlab hook: mising deployhook URL")

            found_site = None
            for idx, website in enumerate(self.inventory[group_index]['websites']):
                if (website['domain'] and website['domain'].lower() == domain) or (website['repo'] and website['repo'] == project['ssh_url_to_repo']):
                    found_site = website['repo']

            if found_site:
                self.log('WARNING', "Project %s already exists" % domain)
                return False
            else:
                site = { 
                    "domain": domain,
                    "repo": '',
                    "type": self.sanitize(site_type)
                }

                if notes is not None:
                    site['notes'] = notes

                site['repo'] = project['ssh_url_to_repo'].encode('utf8')
                self.log('INFO', "Created %s." % project['ssh_url_to_repo'].encode('utf8'))

                self.inventory[group_index]['websites'].append(site)
                self.save()

                self.log('INFO', "Added project %s" % domain)

                return project
        else:
            self.log('ERROR', "Group %s does not exist in gitlab" %  group_path)
        return False

    def sites_edit(self, domain, edits):
        for group in self.inventory:
            for site in group['websites']:
                if site['domain'] == domain:
                    for key, value in edits.items():
                        site[key] = value
                    self.save()
                    return True
            else:
                return False

    def sites_delete(self, domain):
        self.log('INFO', "Attempting to delete site '%s'" % domain)

        group_index = None
        site_index = None
        for gidx, group in enumerate(self.inventory):
            for sidx, site in enumerate(group['websites']):
                if site['domain'] == domain:
                    group_index, site_index = gidx, sidx
                    break

        if group_index is None:
            self.log('WARNING', "Group not found for domain '%s'" % domain)
            return False
        if site_index is None:
            self.log('WARNING', "Site not found for domain '%s'" % domain)
            return False

        with_site_len = len(self.inventory[group_index]['websites'])
        del self.inventory[group_index]['websites'][site_index]

        self.save()

        # Commenting out until further versions. We'll want to add a lot of 
        # prompting and warnings.
        #if self.git.deleteproject(domain.replace('.', '-')):
        #    self.log('INFO', "Project removed from Gitlab")

        if with_site_len > len(self.inventory[group_index]['websites']):
            self.log('INFO', "Site successfully deleted")
            return True

        self.log('INFO', "No sites deleted")
        return False

    def machines_exist(self):
        if 'machines' not in self.settings:
            return False
        if len(self.machines.items()) == 0:
            return False
        return True

    def machine_exists(self, key):
        """ Checks if the machine exists by the given key """
        for machine in self.machines.items():
            (mkey, details) = machine
            if mkey == key:
                return True
        else:
            return False

    def machines_list(self):
        table = PrettyTable(['Machine Name', 'Title', 'Description', 'FQDN', 'IP', 'Services'])
        table.align = 'l'
        table.padding_width = 1
        table.hrules = True
        result = ''

        if not self.machines.items():
            result += 'Example Machines List'
            table.add_row([
                'XXXelmp01 (example)', 
                'Development Machine (example)', 
                'Virtual 2X4 with 4GB RAM (example)', 
                'XXXelmp01.example.com (example)', 
                '127.0.0.1 (example)', 
                'mysqld (example)'
            ])
        else:
            result += 'Current machines:'
            for machine in self.machines.items():
                (key, details) = machine

                # Get the services
                services = ''
                if 'services' in details:
                    for idx, s in enumerate(details['services']):
                        services += '%s' % s['name']
                        if (idx + 1) < len(details['services']):
                            services += '\n'

                table.add_row([
                    key, 
                    details['title'],
                    details['description'], 
                    details['fqdn'], 
                    details['ip'], 
                    services
                ])
        return result + '\n' + table.get_string()

    def machines_add(self, name, title, description, fqdn, ip, services):
        name = self.sanitize(name, True)

        if name not in self.machines:
            self.machines[name] = {}
        else:
            self.log('WARNING', "Machine %s is being overwritten from %s" % (name, self.machines[name]))

        self.machines[name] = {
            "title": self.sanitize(title),
            "description": self.sanitize(description),
            "fqdn": self.sanitize(fqdn),
            "ip": self.sanitize(ip),
        }

        if services:
            self.machines[name]['services'] = []
            for service in services:
                self.machines[name]['services'].append({
                    'name': self.sanitize(service['service']),
                })

        self.save()
        self.log('INFO', "Machine '%s' added" % name)

    def machines_edit(self, key, edits):
        for machine in self.machines.items():
            (mkey, details) = machine
            if mkey == key:
                for k, v in edits.items():
                    details[k] = self.sanitize(v)
                self.save()
                return True
        else:
            return False
    
    def machines_delete(self, key):
        logger.debug("Attempting to delete machine '%s'" % key)

        if key not in self.machines:
            self.log('WARNING', "Attempting to remove '%s' from machines but it does not exist" % key)

        for env in self.environments.items():
            (ekey, details) = env

            if 'vcs_machines' in details:
                for idx, m in enumerate(details['vcs_machines']):
                    if m['machine'] == key:
                        self.log('ERROR', "Failed to delete, machine in use")
                        return False

            # Now the db machines
            if 'db_machines' in details:
                for idx, m in enumerate(details['db_machines']):
                    if m['machine'] == key:
                        self.log('ERROR', "Failed to delete, machine in use")
                        return False

        with_machine_len = len(self.machines)
        del self.machines[key]
        self.save()
        if with_machine_len > len(self.machines):
            self.log('INFO', "Machine successfully deleted")
            return True
        self.log('WARNING', "No machines deleted")
        return False

    def checkout(self, project_id, limit_branches=None):
        git_project = self.git.getproject(project_id)

        #Look for project by name
        if not git_project:
            project_id = project_id.replace(".","-")
            git_project = self.git.findproject(project_id)
            if git_project:
                git_project = self.git.getproject(git_project['id'])

        if not git_project:
            self.log('ERROR', "Unable to load project %s" % project_id)
        else:
            self.log('ERROR', "Found project to checkout %s" % git_project['ssh_url_to_repo'])

        git_branches = self.git.getbranches(git_project['id']) 
        git_branch_list = []

        for f in git_branches:
            # We want to make sure we don't try to checkout any branch that 
            # doesn't exist or that isn't in limit_branches
            if not limit_branches or (limit_branches and f['name'] in limit_branches):
                git_branch_list.append(f['name'])

        for group in self.inventory:
            for website in group['websites']:
                if website['repo'] == git_project['ssh_url_to_repo']:
                    for env_name in website['environments']:
                        if "vcs_machines" in self.environments[env_name] and website['environments'][env_name]['vcs'][0]['branch'] in git_branch_list:
                            for machine in self.environments[env_name]['vcs_machines']:
                                fqdn = self.machines[machine['machine']]['fqdn']
                                extra_vars = {
                                    'fqdn': fqdn,
                                    'webroot': machine['webroot'],
                                    'domain': website['domain'],
                                    'environment_name': env_name
                                }

                                confd = "%s/%s.%s" % (self.settings['webserver']['config_path'], env_name, website['domain'])
                                wrapper_args = {
                                    'logger': logger, 
                                    'verbosity': self.verbosity, 
                                    'cascade_buffer': self.cascade_buffer, 
                                    'pattern': fqdn, 
                                    'module_vars': extra_vars
                                }
                                driver = BMAnsibleWrapper(**wrapper_args)
                                result = driver.checkout(git_project['ssh_url_to_repo'], 
                                                         website['environments'][env_name]['vcs'][0]['branch'],
                                                         machine['webroot'], 
                                                         website['domain'], 
                                                         confd)
                                self.results.update(result)
        return self.results

    def merge(self, project_url, source_branch, dest_branch):
        if source_branch == dest_branch:
           return True

        # Get the Project ID.
        git_project_id = 0
        parsed_git_url = gitparse(project_url, False)

        if parsed_git_url.repo is None:
            # Failed to get project via repository URL, try project name.
            project_url = project_url.replace(".", "-")
            git_project = self.git.findproject(project_url)
            if git_project and 'id' in git_project:
                git_project_id = git_project['id']
        else:
            git_projects = self.git.searchproject(parsed_git_url.repo)

            if not git_projects:
                self.log('ERROR', "Unable to load project %s. Check that projects exist and correct permissions are set." % project_url)
                self.results = {
                    'gitlab': {
                           'status': 'Failed'
                     }
                }
                return False

            for git_project in git_projects:
                if git_project['ssh_url_to_repo'] == project_url:
                    git_project_id = git_project['id']

        if not git_project_id:
            self.log('ERROR', "Unable to load project %s. Check that the project exists." % project_url)
            self.results = {
                'gitlab': {
                       'status': 'Failed'
                 }
            }
            return False
        else:
            self.log('INFO', "Found project %s" % project_url)

        branches = self.git.getbranches(git_project_id)

        if not any([branch for branch in branches if branch['name'] and branch['name'] == source_branch]):
            if any([branch for branch in branches if branch['name'] and branch['name'] == "master"]):
                self.results['newsourcebranch'] = self.git.createbranch(git_project_id, source_branch, "master")

                if self.results['newsourcebranch']:
                    self.log('INFO', "Branch %s created from master for %s" % (source_branch, project_url))
                else:
                    self.log('ERROR', "Failed trying to create branch %s in %s" % (source_branch, project_url))
                    self.results['newsourcebranch']['status'] = "Failed"
                    return False
            else:
                self.log('ERROR', "Branches %s and master do not exist in %s " % (source_branch, project_url))
                self.results = {
                    'gitlab': {
                       'status': 'Failed'
                     }
                }
                return False

        if not any([branch for branch in branches if branch['name'] and branch['name'] == dest_branch]):
            self.results['newdestbranch'] = self.git.createbranch(git_project_id, dest_branch, source_branch)

            if self.results['newdestbranch']:
                self.log('INFO', "Branch %s created from %s for %s" % (dest_branch, source_branch, project_url))
            else:
                self.log('ERROR', "Failed trying to create branch %s in %s" % (dest_branch, project_url))
                self.results['newdestbranch']['status'] = "Failed"
                return False
        else:
            date_tag = datetime.now(timezone("US/Eastern")).strftime("%Y-%m-%d_%H-%M-%S")

            self.results['tagrequest'] = self.git.createrepositorytag(git_project_id, "PREMERGE_%s" % date_tag, dest_branch, "Before %s in to %s on %s" %(source_branch, dest_branch,date_tag))
            self.results['mergerequest'] = self.git.createmergerequest(git_project_id, source_branch, dest_branch, "Automated Merge")

            if not self.results['mergerequest']:
                self.log('ERROR', "Unable to create merge request for %s.\n\nCheck to see if there is already a merge request pending here:\n\n%s/%s/%s/merge_requests" % (project_url,self.git_url, parsed_git_url.owner, parsed_git_url.repo))
                self.results['mergerequest'] = { 'status':  "Failed" }
                return False
            else:
                self.log('INFO', "Created merge request %s/%s/%s/merge_requests/%s" % (self.git_url, parsed_git_url.owner, parsed_git_url.repo, self.results['mergerequest']['iid']))

            self.results['mergechanges'] = self.git.getmergerequestchanges(git_project_id, self.results['mergerequest']['id'])
            if not self.results['mergechanges']['changes']:	
                self.log('INFO', "No changes to merge. Closing merge request.")
                self.results['closemerge'] = self.git.updatemergerequest(git_project_id, self.results['mergerequest']['id'], state_event="close")
                if not self.results['closemerge']:
                     self.log('INFO', "Unable to close merge.")
                     self.results['closemerge'] = { 'status': "Failed" }
		     return False
                else:
                     return True

            self.results['mergeaccept'] = self.git.acceptmergerequest(git_project_id, self.results['mergerequest']['id'])

            if not self.results['mergeaccept']:
                self.log('ERROR', "Unable to accept merge request.  Check the merge request for more details.")
                self.results['mergeaccept'] = { 'status': "Failed" }
                return False
            else:
                self.log('INFO', "Merged %s into %s.  A checkout has been initiated." % (source_branch, dest_branch))

    def asset_sync(self, asset, source_machine, dest_machine, destination, pull=False, relative=True):
        source_machine = self.fqdn_lookup(source_machine)[0]
        dest_machine= self.fqdn_lookup(dest_machine)[0]

        dest_driver = BMAnsibleWrapper(logger, self.verbosity, self.cascade_buffer, pattern=dest_machine)

        if source_machine == dest_machine:
            self.results = dest_driver._transfer_file(asset, None, destination, pull, relative)
        else:
            self.results = dest_driver._transfer_file(asset, source_machine, destination, pull, relative)

    def db_copy(self, database, source_machine, dest_machine, dest_database):
        """ Copies a database between Ansible machines. """
        source_machine = self.fqdn_lookup(source_machine)
        source_machine= source_machine[0]
        dest_machine= self.fqdn_lookup(dest_machine)
        dest_machine= dest_machine[0]

        source_databases = database.split(",")
        dest_databases = dest_database.split(",") if (dest_database) else source_databases

        source_driver = BMAnsibleWrapper(logger, self.verbosity, self.cascade_buffer, pattern=source_machine)
        dest_driver = BMAnsibleWrapper(logger, self.verbosity, self.cascade_buffer, pattern=dest_machine)

        for index in range(len(source_databases)):
            source_database = source_databases[index]
            dest_db = dest_databases[index]

            #backup the source db
            source_backup_file = source_driver._create_backup(source_database)

            if not source_backup_file:
                self.results = {
                    source_machine: {
                        'status': 'Failed',
                        'msg': "Could not back up %s" % source_backup_file
                    }
                }
            else:
                #backup the dest db
                dest_backup_file = dest_driver._create_backup(dest_db)

                if not dest_backup_file:
                    self.results = {
                        dest_machine: {
                            'status': 'Failed',
                            'msg': "Could not back up %s" % dest_backup_file
                        }
                    }
                else:
                    #transfer the file
                    transfer_results = None
                    if source_machine == dest_machine:
                        transfer_results = source_driver._transfer_file(source_backup_file, None, "/tmp")
                    else:
                        transfer_results = source_driver._transfer_file(source_backup_file, dest_machine, "/tmp")

                    if not transfer_results:
                        self.results = {
                            source_machine: {
                                'status': 'Failed',
                                'msg': "Could not transfer up %s" % source_backup_file
                            }
                        }
                    else:
                        #import the source into the destination
                        import_results = dest_driver._import_backup("/tmp%s" % source_backup_file, dest_db)

                        print source_backup_file
                        if not import_results:
                            self.results = {
                                dest_machine: {
                                    'status': 'Failed',
                                    'msg': "Could not import /tmp/%s" % source_backup_file
                                }
                            }
                        else:
                            self.results =  {
                                source_machine: {
                                    'status': 'Success',
                                    'msg': "Backed up to %s" % source_backup_file
                                },
                                dest_machine: {
                                    'status': 'Success', 
                                    'msg': "Replaced %s" % dest_backup_file
                                }
                            }

    def env_machines(self, env):
        machines_list = []

        # Get all VCS machines
        [machines_list.append(vcsm['machine']) 
         for vcsm in self.environments[env]['vcs_machines']
         if vcsm['machine'] not in machines_list]

        # Now the DB machines
        [machines_list.append(dbm['machine']) 
         for dbm in self.environments[env]['db_machines']
         if dbm['machine'] not in machines_list]

        return machines_list

    def env_restart(self, env):
        machines_list = self.env_machines(env)
        valid_services = ['httpd', 'apache', 'apache2', 'nginx']

        for m in self.machines.items():
            (key, details) = m
            if key in machines_list and 'fqdn' in details and 'services' in details:
                [self.restart(s['name'], details['fqdn'])
                 for s in details['services']
                 if s['name'] in valid_services]
   
    def fqdn_lookup(self, machines):
        machines = machines.replace(" ", "")
        machines = machines.split(",")
        machine_list = []
        for key, details in self.machines.items():
            if 'fqdn' in details and (key in machines or details['fqdn'] in machines):
                machine_list.append(details['fqdn'])
        return machine_list
        

    def restart(self, service, machines):
        """ Restarts a service on one or many machines. """
        results = None

        try:
            self.log('INFO', 'Establishing ansible driver...')
            restart_machines = self.fqdn_lookup(machines)
            driver = BMAnsibleWrapper(logger, self.verbosity, self.cascade_buffer, pattern=restart_machines)
            self.log('INFO', 'Restarting service')
            results = driver.restart(service)
        except Exception as e:
            self.loge("Failed to restart service' %s': %s" % (service, str(e)))
            return False

        self.results = results
        return results

    def print_results(self):
        if not self.results:
            exit(0)

        # TODO: What should we actually do with these results?
        try:
            for (hostname, result) in self.results.items():
                if ('status' in result and result['status'] == 'Failed'):
                   exit(1)
        except TypeError as e:
            exit(1)

    def add_vcs_machine(self, env, machine, webroot):
        env = self.sanitize(env, True)
        if not os.path.isabs(webroot):
            self.log('ERROR', "%s is not an absolute path" % webroot)
        else:
            if "vcs_machines" not in self.environments[env]:
                self.environments[env]['vcs_machines'] = []
            if not any([gitmachine for gitmachine 
                        in self.environments[env]['vcs_machines']
                        if gitmachine['machine'] 
                            and gitmachine['machine'] == machine]):
                self.environments[env]['vcs_machines'].append({
                    "machine": machine,
                    "webroot": webroot
                })
                self.save()
                self.log('INFO', "Webroot %s:%s added to env %s" % (machine, webroot, env))
                return True
            else:
                self.log('WARNING', "Webroot %s:%s already exists in env %s" % (machine, webroot, env))

        return False

    def delete_vcs_machine(self, env, machine):
        env = self.sanitize(env, True)
        if env not in self.environments:
            self.log('ERROR', "Environment %s not found" % env)
            return
        machine = self.sanitize(machine)

        with_vcs_len = len(self.environments[env]['vcs_machines'])
        self.environments[env]['vcs_machines'][:] = [vcs for vcs in self.environments[env]['vcs_machines'] if vcs['machine'] != machine]
        self.save()
        if with_vcs_len > len(self.environments[env]['vcs_machines']):
            self.log('INFO', "VCS machine successfully deleted")
            return True
        self.log('WARNING', "No VCS machines deleted")
        return False

    def env_exists(self, env):
        """ Checks if an environment exists. """
        return self.sanitize(env, True) in self.environments

    def vcs_machine_exists(self, env, machine):
        if not self.env_exists(env):
            return False

        for git in self.environments[env]['vcs_machines']:
            if git['machine'] == machine:
                return True
        return False

    def db_machine_exists(self, env, machine):
        if not self.env_exists(env):
            return False

        env = self.sanitize(env, True)
        if 'db_machines' in self.environments[env]:
            for db in self.environments[env]['db_machines']:
                if db['machine'] == machine:
                    return True
        return False

    def add_db_machine(self, env, machine):
        env = self.sanitize(env, True)
        if env not in self.environments:
            return False

        if "db_machines" not in self.environments[env]:
            self.environments[env]['db_machines'] = []

        if not any([dbmachine for dbmachine 
                    in self.environments[env]['db_machines'] 
                    if dbmachine['machine'] 
                        and dbmachine['machine'] == machine]):
            self.environments[env]['db_machines'].append({ "machine": self.sanitize(machine) })
            self.save()
            self.log('INFO', "Database %s added to env %s" % (machine, env))
            return True
        
        self.log('WARNING', "Database %s already exists in env %s" % (machine, env))
        return False

    def delete_db_machine(self, env, machine):
        env = self.sanitize(env, True)
        if env not in self.environments:
            self.log('ERROR', "Environment %s not found" % env)
            return
        machine = self.sanitize(machine)

        with_db_len = len(self.environments[env]['db_machines'])
        self.environments[env]['db_machines'][:] = [db for db in self.environments[env]['db_machines'] if db['machine'] != machine]
        self.save()
        if with_db_len > len(self.environments[env]['db_machines']):
            self.log('INFO', "DB machine successfully deleted")
            return True
        self.log('WARNING', "No DB machines deleted")
        return False
        
    def validate_deploy(self, domain, site_index, env):
        if site_index is None:
            self.log('WARNING', "Unable to find website %s in %s" % (domain, self.settings_path))
            return False

        try:
            if env not in self.environments:
                self.log('ERROR', "Environment %s not found" % env)
                return False
        except Exception as e:
            self.loge("Failed to validate deployments.")

        return True

    def add_code_deploy(self, domain, env, branch):
        domain = self.sanitize(domain, True)
        env = self.sanitize(env, True)

        group_index = None
        site_index = None
        
        for gidx, group in enumerate(self.inventory):
            for sidx, site in enumerate(group['websites']):
                if site['domain'] == domain:
                    group_index, site_index = gidx, sidx
                    break

        if not self.validate_deploy(domain, site_index, env):
            self.log('WARNING', "Failed to validate the code deploy")
            return False

        if "environments" not in self.inventory[group_index]['websites'][site_index]:
            self.inventory[group_index]['websites'][site_index]['environments'] = {}
        
        if env not in self.inventory[group_index]['websites'][site_index]['environments']:
            self.inventory[group_index]['websites'][site_index]['environments'][env] = {}

        if 'vcs' not in self.inventory[group_index]['websites'][site_index]['environments'][env]:
            self.inventory[group_index]['websites'][site_index]['environments'][env]['vcs'] = []

        self.inventory[group_index]['websites'][site_index]['environments'][env]['vcs'].append({
            'branch': self.sanitize(branch)
        })

        self.save()
        self.log('INFO', "%s added to %s for %s" % (branch, env, domain))

    def delete_code_deploy(self, domain, env, branch):
        domain = self.sanitize(domain, True)
        env = self.sanitize(env, True)

        group_index = None
        site_index = None
        for gidx, group in enumerate(self.inventory):
            for sidx, site in enumerate(group['websites']):
                if site['domain'] == domain:
                    group_index, site_index = gidx, sidx
                    break

        deploys = self.inventory[group_index]['websites'][site_index]['environments'][env]['vcs']
        with_vcs_len = len(deploys)
        deploys[:] = [vcs for vcs in deploys if vcs['branch'] != self.sanitize(branch)]
        self.save()

        if with_vcs_len > len(deploys):
            self.log('INFO', "Code deploy successfully deleted")
            return True
        self.log('WARNING', "No code deployments deleted")
        return False

    def add_db_deploy(self, domain, env, db):
        domain = self.sanitize(domain, True)
        env = self.sanitize(env, True)
        db = self.sanitize(db, True)

        group_index = None
        site_index = None
        for gidx, group in enumerate(self.inventory):
            for sidx, site in enumerate(group['websites']):
                if site['domain'] == domain:
                    group_index, site_index = gidx, sidx
                    break

        if not self.validate_deploy(domain, site_index, env):
            return False
        
        if "environments" not in self.inventory[group_index]['websites'][site_index]:
            self.inventory[group_index]['websites'][site_index]['environments'] = {}

        if "db" not in self.inventory[group_index]['websites'][site_index]['environments'][env]:
            self.inventory[group_index]['websites'][site_index]['environments'][env]['db'] = []

        for existing_db in self.inventory[group_index]['websites'][site_index]['environments'][env]['db']:
            if existing_db['name'] == db:
                self.log('WARNING', "DB %s already in %s for %s" % (db, env, domain))
                break
        else:
            self.inventory[group_index]['websites'][site_index]['environments'][env]['db'].append({
                "name": db
            })
            self.log('INFO', "%s added to %s for %s" % (db, env, domain))

        self.save()

    def delete_db_deploy(self, domain, env, db):
        domain = self.sanitize(domain, True)
        env = self.sanitize(env, True)
        db = self.sanitize(db, True)

        group_index = None
        site_index = None
        for gidx, group in enumerate(self.inventory):
            for sidx, site in enumerate(group['websites']):
                if site['domain'] == domain:
                    group_index, site_index = gidx, sidx
                    break


        deploys = self.inventory[group_index]['websites'][site_index]['environments'][env]['db']
        with_db_len = len(deploys)
        deploys[:] = [db_deploy for db_deploy in deploys if db_deploy['name'] != db]
        self.save()

        if with_db_len > len(deploys):
            self.log('INFO', "DB deploy successfully deleted")
            return True
        self.log('WARNING', "No DB deployments deleted")
        return False

    def add_asset_deploy(self, domain, env, path):
        domain = self.sanitize(domain, True)
        env = self.sanitize(env, True)
        path = self.sanitize(path)

        # Path delimiter fine since we don't support Windows..
        path_list = filter(None, path.split("/")) if path else None
        title = path_list[-1] if path_list else None

        group_index = None
        site_index = None
        for gidx, group in enumerate(self.inventory):
            for sidx, site in enumerate(group['websites']):
                if site['domain'] == domain:
                    group_index, site_index = gidx, sidx
                    break
	print env
        if not self.validate_deploy(domain, site_index, env):
            self.log('ERROR', "Failed to validate deploys for env %s" % env)
            return False
        
        try:
            if "environments" not in self.inventory[group_index]['websites'][site_index]:
                self.inventory[group_index]['websites'][site_index]['environments'] = {
                    env: {}
                }

            if env not in self.inventory[group_index]['websites'][site_index]['environments']:
                self.inventory[group_index]['websites'][site_index]['environments'][env] = {}

            if "assets" not in self.inventory[group_index]['websites'][site_index]['environments'][env]:
                self.inventory[group_index]['websites'][site_index]['environments'][env]['assets'] = []
        except Exception as e:
            self.loge(e)
            return False

        for existing_asset in self.inventory[group_index]['websites'][site_index]['environments'][env]['assets']:
            if existing_asset['path'] == path:
                self.log('WARNING', "Asset %s already in %s for %s" % (title, env, domain))
                break
        else:
            self.inventory[group_index]['websites'][site_index]['environments'][env]['assets'].append({
                'title': title,
                'path': path,
            })
            self.log('INFO', "%s added to %s for %s" % (title, env, domain))

        self.save()

    def delete_asset_deploy(self, domain, env, path):
        domain = self.sanitize(domain, True)
        env = self.sanitize(env, True)
        path = self.sanitize(path)

        group_index = None
        site_index = None
        for gidx, group in enumerate(self.inventory):
            for sidx, site in enumerate(group['websites']):
                if site['domain'] == domain:
                    group_index, site_index = gidx, sidx
                    break


        deploys = self.inventory[group_index]['websites'][site_index]['environments'][env]['assets']
        with_asset_len = len(deploys)
        deploys[:] = [asset_deploy for asset_deploy in deploys if asset_deploy['path'] != path]
        self.save()

        if with_asset_len > len(deploys):
            self.log('INFO', "Asset deploy successfully deleted")
            return True
        self.log('WARNING', "No asset deployments deleted")
        return False

    def create_database(self, db_name, machines, env, domain, webroots=None):
        """Initializes the BMAnsibleWrapper driver and creates a database. """
        fqdns = []
        for m in self.machines.items():
            (key, details) = m
            if key in machines and 'fqdn' in details:
                fqdns.append(details['fqdn'])

        driver = BMAnsibleWrapper(logger, self.verbosity, self.cascade_buffer, pattern=','.join(fqdns))
        db_pass = driver.generate_password()
        driver.create_database(db_name, db_user=db_name, db_pass=db_pass)
        options = {
            'db_name': db_name,
            'db_pass': db_pass,
            'db_user': db_name
        }

        # Save settings and transfer any files that need to be transfered.
        # Use webroots and default to env/domain if they do not exist.
        if webroots is None:
            webroots = ['/var/www/cascade/%s/%s' % (env, domain)]
        
        for webroot in webroots:
            settings_dir = webroot + ('/%s' % domain)

            # Write or update the *.ini file.
            if not os.path.exists(settings_dir):
                os.makedirs(settings_dir)
            
            db_settings = ConfigParser.RawConfigParser()
            db_settings.read(settings_dir + '/%s.ini' % self.sanitize(domain, True))
        
            if db_settings.has_section(options['db_name']):
                # TODO: do we want to update the option values?
                pass
            else:
                db_settings.add_section(options['db_name'])
                db_settings.set(options['db_name'], 'db_pass', options['db_pass'])
                db_settings.set(options['db_name'], 'db_user', options['db_user'])
        
            with open(settings_dir + '/%s.ini' % self.sanitize(domain, True), 'wb') as configfile:
                db_settings.write(configfile)

            driver.push_database_settings(settings_dir, settings_dir, '%s.ini' % self.sanitize(domain, True))

    def env_has_dbs(self, env):
        if env in self.environments and 'db_machines' in self.environments[env] and len(self.environments[env]['db_machines']) > 0:
            return True
        return False

    def env_has_vcs(self, env):
        if env in self.environments and 'vcs_machines' in self.environments[env] and len(self.environments[env]['vcs_machines']) > 0:
            return True
        return False

    def find_symlinks(self, fqdn, docroot):
        wrapper_args = {
            'logger': logger, 
            'verbosity': self.verbosity, 
            'cascade_buffer': self.cascade_buffer, 
            'pattern': fqdn,
        }
        driver = BMAnsibleWrapper(**wrapper_args)
        return driver.find_symlinks(docroot)

    def find_known_ignored(self, fqdn, docroot, known_ignored):
        wrapper_args = {
            'logger': logger, 
            'verbosity': self.verbosity, 
            'cascade_buffer': self.cascade_buffer, 
            'pattern': fqdn,
        }
        driver = BMAnsibleWrapper(**wrapper_args)
        return driver.find_known_ignored(docroot, known_ignored)

    def git_ignore_add(self, fqdn, origin, docroot, ignore_paths):
        wrapper_args = {
            'logger': logger, 
            'verbosity': self.verbosity, 
            'cascade_buffer': self.cascade_buffer, 
            'pattern': fqdn,
        }
        driver = BMAnsibleWrapper(**wrapper_args)
        driver.git_ignore_add(docroot, ignore_paths)
 
    def git_commit_push(self, fqdn, docroot):
        wrapper_args = {
            'logger': logger, 
            'verbosity': self.verbosity, 
            'cascade_buffer': self.cascade_buffer, 
            'pattern': fqdn,
        }
        driver = BMAnsibleWrapper(**wrapper_args)
        driver.git_commit_push(docroot)

    def git_add_origin(self, fqdn, docroot, origin):
        wrapper_args = {
            'logger': logger, 
            'verbosity': self.verbosity, 
            'cascade_buffer': self.cascade_buffer, 
            'pattern': fqdn, # TODO
        }
        driver = BMAnsibleWrapper(**wrapper_args)
        driver.git_add_origin(docroot, origin)
