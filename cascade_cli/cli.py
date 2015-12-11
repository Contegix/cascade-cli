import rpyc
import click
from click.exceptions import Abort
import socket
import ConfigParser

# Echo wrappers.
def error(text):
    click.secho(text, fg="red")

def warn(text):
    click.secho(text, fg="yellow")

def debug(text):
    click.secho(text, fg="white")

def info(text):
    click.secho(text, fg="white")

# Prompts
def prompt(text, type=None, default=None):
    return click.prompt(click.style(text,"cyan"), type=type, default=default)

def confirm_prompt(text):
    return click.confirm(click.style(text, "yellow")) 

# Entity prompts, ensures we have proper input.
def env_prompt(config, env, prompt_text):
    """Ensures that we have a valid environment and prompts if we don't. """
    def _env_prompt(config, prompt_text):
        env = None
        if not config.envs_exist():
            warn('No environments exist!')
        else:
            while not env:
                click.echo(config.envs_list())
                env_check = prompt(prompt_text, type=str)
                if config.env_exists(env_check):
                    env = env_check
                else:
                    warn('Environment does not exist!')
        return env
    
    if not env:
        env = _env_prompt(config, prompt_text)
    elif not config.env_exists(env):
        warn('Environment does not exist!')
        env = _env_prompt(config, prompt_text)
    return env

# Set default to fall back on.
cascade_host = 'localhost'
cascade_port = 18861
cascade_path = '/etc/cascade-cli/settings.yml'

try:
    # Load any local config settings.
    local_config = ConfigParser.RawConfigParser()
    local_config.read('/etc/cascade-cli/config.ini')
    cascade_path = local_config.get('cascade', 'path')

    # Setup remote access 
    cascade_host = local_config.get('cascade', 'host')
    cascade_port = local_config.getint('cascade', 'port')
except Exception as e:
    error(e)

def print_cascade_buffer(cbuffer):
    click.echo(cbuffer)

try:
    debug("Connecting to %s on port %s" % (cascade_host, cascade_port))
    cascade_conn = rpyc.connect(cascade_host, cascade_port)
    bgsrv = rpyc.BgServingThread(cascade_conn)
    cascade_buffer = cascade_conn.root.CascadeBuffer(print_cascade_buffer)
except Exception as e:
    click.echo(e)
    exit(1)

def cleanup():
    """Ensures we stop any threads and close connections. """
    cascade_buffer.stop()
    bgsrv.stop()
    cascade_conn.close()

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

def set_verbosity(ctx, param, value):
    if value:
       ctx.obj.set_verbosity(value)

def env_standardize(config, name):
    # Format the env name for web root suggestion.
    if name.lower() == 'development':
        name = 'dev'
    elif name.lower() == 'staging':
        name = 'stage'
    elif name.lower() == 'production':
        name = 'prod'
    else:
        name = config.sanitize(name, True)
    return name

@click.group(invoke_without_command=True)
@click.option('-v', '--verbosity', count=True)
@click.pass_context
def cli(ctx, verbosity):
    ctx.obj = cascade_conn.root.CascadeConfig(cascade_path, cascade_buffer, verbosity)
    if not ctx.args:
        ctx.invoke(interactive)

@cli.resultcallback()
@click.pass_context
def print_results(ctx, *args, **kwargs):
    ctx.obj.print_results()

@cli.command(help='Starts Cascade CLI in interactive mode')
@click.option('-v', '--verbosity', count=True, callback=set_verbosity, expose_value=False, is_eager=True)
@click.pass_context
def interactive(ctx):
    click.clear()
    click.echo('Cascade CLI v1.4:')
    click.echo('-----------------------------')
    ctx.obj.clear_backdoor_user()
    username = prompt("Backdoor login (your username)")
    password = prompt("Backdoor password (ticket #)")
    ctx.obj.save_backdoor_user(username, password)

    while True:
        click.echo('Cascade CLI Main Menu:')
        click.echo('----------------------------')
        click.echo('[0] Exit')
        click.echo('[1] Manage roles')
        click.echo('[2] Manage machines')
        click.echo('[3] Manage environments')
        click.echo('[4] Manage groups')
        click.echo('[5] Manage sites')
    
        value = prompt("Option")

        if value == 'exit' or value == 'quit' or value == 'q':
            ctx.obj.clear_backdoor_user()
            break

        try:
            value = int(value)

            if value == 0:
                ctx.obj.clear_backdoor_user()
                break
            elif value == 1:
                ctx.invoke(roles_interactive, True)
            elif value == 2:
                ctx.invoke(machines_interactive, True)
            elif value == 3:
                ctx.invoke(envs_interactive, True)
            elif value == 4:
                ctx.invoke(groups_interactive, True)
            elif value == 5:
                ctx.invoke(sites_interactive, True)
            else:
                warn(click,'Option not available')
        except Exception as e:
            warn('Invalid option.')
        click.clear()

@cli.group(invoke_without_command=True, help='List or modify roles')
@click.pass_context
def roles(ctx):
    if not ctx.args:
        ctx.invoke(roles_interactive)

@roles.command('interactive', help='Manage roles in interactive mode')
@click.option('-v', '--verbosity', count=True, callback=set_verbosity, expose_value=False, is_eager=True)
@click.pass_context
def roles_interactive(ctx, from_main_menu=False):
    if from_main_menu:
        exit_term = 'Back'
    else:
        exit_term = 'Exit'

    click.clear()
    while True:
        click.echo('[0] %s' % exit_term)
        click.echo('[1] %s' % roles_list.short_help)
        click.echo('[2] %s' % roles_add.short_help)
        click.echo('[3] %s' % roles_delete.short_help)

        try:
            value = prompt("Option", type=int)
            if value == 0:
                break
            elif value == 1:
                ctx.invoke(roles_list)
            elif value == 2:
                ctx.invoke(roles_add)
            elif value == 3:
                ctx.invoke(roles_delete)
            else:
                warn('Option not available')
        except Abort as e:
            click.secho('Aborting...\n', fg="red")

@roles.command('list', help='List the current roles')
@click.pass_obj
def roles_list(config):
    debug('Getting roles from config...')
    click.echo(config.roles_list())

@roles.command('add', help='Add a role to Cascade')
@click.option('--title', default='', type=str, help='Title of role, eg. Web Admins')
@click.pass_obj
def roles_add(config, title):
    if not title or not config.role_exist(config.sanitize(title, True)):
        while not title:
            click.echo(config.roles_list())
            title_check = prompt('Enter title of role to add', type=str)
            if config.role_exist(config.sanitize(title_check, True)):
                warn('Role already exists')
            else:
                title = title_check
    elif config.role_exist(config.sanitize(title, True)):
        warn('Role already exists')
        return

    config.roles_add(title)

@roles.command('delete', help='Delete an existing role')
@click.option('--machine_name', default='', type=str)
@click.option('--force', is_flag=True)
@click.pass_obj
def roles_delete(config, machine_name, force):
    if not config.roles_exist():
        warn('No roles exist!')
        return

    if not machine_name or not config.role_exist(machine_name):
        while not machine_name:
            click.echo(config.roles_list())
            machine_name_check = prompt('Enter "Machine Name" of role to delete', type=str)
            if not config.role_exist(machine_name_check):
                warn('Name does not exist. Select a valid role name')
            else:
                machine_name = machine_name_check

    if force:
        config.roles_delete(machine_name)
    else:
        if confirm_prompt("Are you sure you want to delete role '%s'?" % machine_name):
            if config.roles_delete(machine_name):
                click.echo('Role %s successfully deleted' % machine_name)
            else:
                click.echo('Role failed to delete')

@cli.group(invoke_without_command=True, help='List or modify sites')
@click.pass_context
def sites(ctx):
    if not ctx.args:
        ctx.invoke(sites_interactive)

@sites.command('interactive', help='Manage sites in interactive mode')
@click.pass_context
def sites_interactive(ctx, from_main_menu=False):
    if from_main_menu:
        exit_term = 'Back'
    else:
        exit_term = 'Exit'

    click.clear()
    while True:
        click.echo('[0] %s' % exit_term)
        click.echo('[1] %s' % sites_list.short_help)
        click.echo('[2] %s' % sites_group_list.short_help)
        click.echo('[3] %s' % sites_add.short_help)
        click.echo('[4] %s' % sites_edit.short_help)
        click.echo('[5] %s' % sites_delete.short_help)
        click.echo('[6] %s' % sites_db_copy.short_help)
        click.echo('[7] %s' % sites_checkout.short_help)
        click.echo('[8] %s' % sites_merge.short_help)
        click.echo('[9] %s' % sites_asset_sync.short_help)

        try:
            value = prompt("Option", type=int)

            if value == 0:
                break
            elif value == 1:
                ctx.invoke(sites_list)
            elif value == 2:
                ctx.invoke(sites_group_list)
            elif value == 3:
                ctx.invoke(sites_add)
            elif value == 4:
                ctx.invoke(sites_edit)
            elif value == 5:
                ctx.invoke(sites_delete)
            elif value == 6:
                ctx.invoke(sites_db_copy)
            elif value == 7:
                ctx.invoke(sites_checkout)
            elif value == 8:
                ctx.invoke(sites_merge)
            elif value == 9:
                ctx.invoke(sites_asset_sync)
            else:
                warn('Option not available')
        except Abort as e:
            click.secho('Aborting...\n', fg="red")

@sites.command('list', help='List all sites')
@click.pass_obj
def sites_list(config):
    click.echo(config.sites_list())

@sites.command('group-list', help='List sites in a group')
@click.option('--group', default='', type=str, help='Group name for listing sites')
@click.pass_obj
def sites_group_list(config, group):
    def _group_prompt():
        group = None
        while not group:
            click.echo(config.groups_list())
            group_check = prompt('Group name for listing sites', type=str)
            if config.group_exists(group_check):
                group = group_check
            else:
                warn('Invalid group path!')
        return group

    if not group:
        group = _group_prompt()
    elif not config.group_exists(group):
        warn('Group does not exist!')
        group = _group_prompt()

    click.echo(config.sites_list(group))

@sites.command('add', help='Add a site')
@click.option('--domain', default='', type=str, help='Domain, eg: example.com')
@click.option('--group_path', default='', type=str, help='Path of group to put the site in')
@click.option('--site_type', default='', type=str, help='The type of site, eg: Drupal7 or Static HMTL')
@click.option('-v', '--verbosity', count=True, callback=set_verbosity, expose_value=False, is_eager=True)
@click.pass_obj
@exit_on_exception
def sites_add(config, domain, group_path, site_type):
    def site_types_prompt():
        site_type = None
        while True:
            click.echo('Available site types:')
            for idx, t in enumerate(config.site_types):
                click.echo('[%s] %s' % (idx, t))
            site_index = prompt('Site Type', type=int)

            if site_index < 0 or site_index > (len(config.site_types) - 1):
                warn('Invalid option.')
            else:
                site_type = config.site_types[site_index]
                break
        return site_type

    if not any([domain, group_path, site_type]):
        click.echo(config.sites_list())

    if not domain:
        while not domain:
            domain_check = prompt('Domain of site (eg. example.com)', type=str)
            if config.site_exists(domain_check):
                warn('Site domain already exists')
            else:
                domain = domain_check

    onboarding_fqdn = prompt("On what machine is the site code currently located", 
                             type=str, default=socket.getfqdn())

    docroot = prompt("Docroot where code is currently located", type=str, 
                     default=("/var/www/onboarding/%s/htdocs" % domain))

    if not group_path:
        while not group_path:
            click.echo(config.groups_list())
            group_path_check = prompt('Group to put site in', type=str)
            if config.group_path_exists(group_path_check):
                group_path = group_path_check
            else:
                warn('Invalid group path!')

    if not site_type:
        site_type = site_types_prompt()
    elif site_type not in config.site_types:
        warn('Invalid Site Type')
        site_type = site_types_prompt()

    
    project_path = prompt("Project path name for repo", type=str, 
                          default=domain.replace('.', '-').replace(' ', '-'))

    git_project = config.sites_add(domain, group_path, site_type, project_path)
    if not git_project:
        return

    known_ignored = _default_known_ignored_files() + _default_known_assets()
    config.git_add_origin(onboarding_fqdn, docroot, git_project['ssh_url_to_repo'])
    paths = _add_ignores(config, onboarding_fqdn, git_project['ssh_url_to_repo'], docroot, known_ignored)
    config.git_commit_push(onboarding_fqdn, docroot)
    potential_assets = [p for p in paths if p not in _default_known_ignored_files()]

    # TODO: refactor so that we're not looping through environments multiple times...
    # Determine how many dev environments we have.
    affected_envs = []

    # Prompt for code deployments.
    for env in config.environments.items():
        (key, details) = env

        if confirm_prompt("Do you want to deploy this site's code to %s" % key):
            affected_envs.append(key)
            branch = prompt("Branch name to associate with %s" % key, type=str, default='bmesh_%s' % env_standardize(config, key))
            source_branch = prompt('Which branch should %s be created from?' % branch, type=str, default="master")
            config.add_code_deploy(domain, key, branch)
            config.merge(git_project['ssh_url_to_repo'], source_branch, branch)
  
            # Restarting httpd so that the server recognizes the new site.
            if confirm_prompt("Would you like to restart %s's web servers?" % key):
                config.env_restart(key)
                
    # Prompt for database deployments.
    if confirm_prompt("Does this site have a database?"):
        add_dbs = True
        while add_dbs:
            
            for env in config.environments.items():
                (key, details) = env
        
                if key not in affected_envs:
                   continue

                default_db = domain.replace(".", "_")

                if not key.startswith('prod'):
                    default_db = '%s_%s' % (env_standardize(config, key), default_db.replace("-","_"))

                db_name = prompt('What is the database name on %s?' % key, type=str, default=default_db)

                env_db_machines = []
                webroots = []

                if 'vcs_machines' in details:
                    for vcs_machine in details['vcs_machines']:
                        if 'webroot' in vcs_machine:
                            webroots.append(vcs_machine['webroot'])

                if 'db_machines' in details:
                    for db_machine in details['db_machines']:
                        if db_machine['machine'] not in env_db_machines:
                            env_db_machines.append(db_machine['machine'])

                    # Create the DB for all DB machines listed in the environment.
                    config.create_database(db_name, env_db_machines, key, domain, webroots)

                    click.echo("If this database needs to be imported from a mysql " \
                               "dump or a database outside of this customer's solution, " \
                               "please do so manually. However, if this database already " \
                               "exists within this customer's solution, then answer yes to " \
                               "the prompt below to begin the copy.")

                    if confirm_prompt("Would you like to copy an existing database into this database?"):
                        click.echo(config.machines_list())
                        source_machine = prompt('Which machine is the database located on?')
                        source_db = prompt('What is the name of the database?')
                        config.db_copy(source_db, source_machine, env_db_machines[0], db_name)

                config.add_db_deploy(domain, key, db_name)

            add_dbs = confirm_prompt('Does this site have another database?') 

    for asset in potential_assets:
        if confirm_prompt("Do you want to sync %s between environments" % asset):
            for env in config.environments.items():
                (key, details) = env
                if key not in affected_envs:
                    continue
                if not asset.startswith("/"):
                    asset = "%s/%s" % (docroot,asset)
                assetguess = asset.replace("/onboarding/","/"+key+"/")
                path = prompt("What is the absolute path of %s on %s" %(asset, key),type=str, default=assetguess)
                config.add_asset_deploy(domain, key, path)

def _add_ignores(config, fqdn, origin, docroot, known_ignored=None):
    if known_ignored is None:
        known_ignored = _default_known_ignored_files() + _default_known_assets()
    paths = []
    patterns = []

    # Prompt if user wants to add symlinks to VCS ignore file.
    symlinks = config.find_symlinks(fqdn, docroot)
    if symlinks:
        info("Add the following symlinks to the ignore file?")
        for link in symlinks:
            if confirm_prompt("%s -> %s" % (link,symlinks[link])):
                paths.append(symlinks[link])
                patterns.append(link)

    # Prompt for known ignores for the same.
    files = config.find_known_ignored(fqdn, docroot, known_ignored)
    if files:
        info("Add the following commonly ignored patterns to the ignore file?")
        for f in files: 
            if files[f] not in patterns and confirm_prompt("Pattern %s (found %s)" % (files[f], f)):
                if files[f] not in _default_known_ignored_files():
                    paths.append(f)
                patterns.append(files[f])

    if confirm_prompt("Would you like to exclude/ignore any additional files or directories (assets, config files, etc)"):
        while True:
            ignore_path = prompt("Path or file to ignore", type=str)
            # TODO: Verify the path/file exists.
            paths.append(ignore_path)
            patterns.append(ignore_path)
            if not confirm_prompt("Ignore another path or file"):
                break

    config.git_ignore_add(fqdn, origin, docroot, patterns)
    return paths

def _default_known_assets():
    # TODO: pull from a config file
    known_assets = [
       './files',
        './private',
        '*sites/*/files',
        '*sites/*/private'
    ]
    return known_assets

def _default_known_ignored_files():
    # TODO: pull from a config file
    known_ignored_files = [
        './settings.php',
        './civicrm.settings.php',
        '*sites/*/settings.php',
        '*sites/*/civicrm.settings.php',
        '*wp-config.php',
        '*wp-content/advanced-cache.php',
        '*wp-content/wp-cache-config.php'
    ]
    return known_ignored_files

@sites.command('edit', help='Edit a site')
@click.argument('domain', required=False)
@click.option('--new_domain', default='', type=str, help='Domain, eg: example.com')
@click.option('--notes', default='', type=str, help='The notes of the site, eg: the tagline')
@click.option('--repo', default='', type=str, help='Git repository location')
@click.option('--site_type', default='', type=str, help='The type of site, eg: Drupal7 or Static HMTL')
@click.pass_obj
def sites_edit(config, domain, new_domain, notes, repo, site_type):
    deploy_prompts = False
    if not any([domain, new_domain, notes, repo, site_type]):
        # If we're missing options we're probably in interactive mode.
        deploy_prompts = True
        
    if not domain:
        if config.sites_exist():
            click.echo(config.sites_list())
        else:
            warn('No sites exist!')
            return

        # Keep prompting for a valid domain.
        while not domain:
            domain_check = prompt('Enter domain of site to edit', type=str)
            if config.site_exists(domain_check):
                domain = domain_check
            else:
                warn('Domain does not exist!')
    elif not config.site_exists(domain):
        warn('Site does not exist!')
        return

    edits = {}

    if not new_domain:
        if confirm_prompt('Change domain?'):
            new_domain = prompt('New domain', type=str)
            edits['domain'] = new_domain
    else:
        edits['domain'] = new_domain

    if not notes:
        if confirm_prompt('Change notes?'):
            notes = prompt('Notes', type=str)
            edits['notes'] = notes
    else:
        edits['notes'] = notes

    if not repo:
        if confirm_prompt('Change repository location?'):
            repo = prompt('New repo location', type=str)
            edits['repo'] = repo
    else:
        edits['repo'] = repo

    if not site_type:
        if confirm_prompt('Change site type?'):
            site_type = prompt('New site type', type=str)
            edits['site_type'] =site_type
    else:
        edits['site_type'] = site_type

    if deploy_prompts:
        prompt_text = 'Add a code deploy?'
        while confirm_prompt(prompt_text):
            prompt_text = 'Add another code deploy?'
            env = env_prompt(config, None, 'Environment to deploy code to')
            branch = prompt('Branch in Gitlab to create from master branch', type=str, default="bmesh_%s" % env)

            config.add_code_deploy(domain, env, branch)
        
        prompt_text = 'Remove a code deploy?'
        while confirm_prompt(prompt_text):
            prompt_text = 'Remove another code deploy?'
            env = env_prompt(config, None, 'Environment to remove a code deploy from')
            branch = prompt('Branch to remove', type=str)

            config.delete_code_deploy(domain, env, branch)

        prompt_text = 'Add a DB deploy?'
        while confirm_prompt(prompt_text):
            prompt_text = 'Add another DB deploy?'
            env = env_prompt(config, None, 'Environment to deploy DB to')
            db = prompt('Database to create on the environment', type=str)

            config.add_db_deploy(domain, env, db)

        prompt_text = 'Remove a DB deploy?'
        while confirm_prompt(prompt_text):
            prompt_text = 'Remove another DB deploy?'
            env = env_prompt(config, None, 'Environment to remove a DB deployment from')
            db = prompt('Database to remove', type=str)

            config.delete_db_deploy(domain, env, db)
        
        prompt_text = 'Add an asset deploy?'
        while confirm_prompt(prompt_text):
            prompt_text = 'Add another asset deploy?'
            env = env_prompt(config, None, 'Environment to add an asset deployment to')
            path = prompt('Path of the assets to deploy', type=str)
            
            config.add_asset_deploy(domain, env, path)

        prompt_text = 'Remove an asset deploy?'
        while confirm_prompt(prompt_text):
            prompt_text = 'Remove another asset deploy?'
            env = env_prompt(config, None, 'Environment to remove an asset deployment from')
            title = prompt('Title of asset deployment to remove', type=str)

            config.delete_asset_deploy(domain, env, title)

    config.sites_edit(domain, edits)

@sites.command('delete', help='Delete a site')
@click.argument('domain', required=False)
@click.option('-f', '--force', is_flag=True)
@click.pass_obj
def sites_delete(config, domain, force):
    if not domain:
        if config.sites_exist():
            click.echo(config.sites_list())
        else:
            warn('No sites exist!')
            return

        # Keep prompting for a valid env.
        while not domain:
            domain_check = prompt('Enter domain of site to delete', type=str)
            if config.site_exists(domain_check):
                domain = domain_check
            else:
                warn('Domain does not exist!')
    elif not config.site_exists(domain):
        warn('Site does not exist!')
        return

    if force:
        debug('Issuing a force delete...')
        config.sites_delete(domain)
    elif confirm_prompt("Are you sure you want to delete '%s'?" % domain):
        #TODO: Prompt to delete files from each env
        #TODO: Prompt to delete databases
        #TODO: Prompt to delete from gitlab
        config.sites_delete(domain)

@sites.command(help='Add a code deploy to a site')
@click.option('--domain', default='', type=str, help='Site domain to deploy, eg. example.com')
@click.option('--env', default='', type=str, help='Environment to deploy to, eg. development)')
@click.option('--branch', default='', type=str, help='Branch in Gitlab to create from master branch, eg. bmesh_dev')
@click.pass_obj
def add_code_deploy(config, domain, env, branch):
    if not domain:
        click.echo(config.sites_list())
        domain = prompt('Site domain to deploy (eg. example.com)', type=str)
    if not env:
        click.echo(config.envs_list())
        env = prompt('Environment to deploy to (eg. development)', type=str)
    if not branch:
        branch = prompt('Branch in Gitlab to create from master branch (eg. bmesh_dev)', type=str)

    config.add_code_deploy(domain, env, branch)

@sites.command(help='Add a db deploy to a site')
@click.option('--domain', default='', type=str, help='Site domain to deploy DB, eg. example.com')
@click.option('--env', default='', type=str, help='Environment to add database to, eg. development')
@click.option('--db', default='', type=str, help='DB to create on environment, eg. dev_drupal')
@click.pass_obj
def add_db_deploy(config, domain, env, db):
    if not domain:
        click.echo(config.sites_list())
        domain = prompt('Site domain to deploy DB (eg. example.com)', type=str)
    if not env:
        click.echo(config.envs_list())
        env = prompt('Environment to add database to (eg. development)', type=str)
    if not db:
        click.echo(config.machines_list())
        db = prompt('Database to create on the environment (eg. dev_drupal)', type=str)

    config.add_db_deploy(domain, env, db)

@sites.command("dbcopy", help='Copy a database')
@click.option('--database', default='', type=str, help='The database to copy')
@click.option('--source_machine', default='', type=str, help='The domain name or ip address of the source database machine')
@click.option('--dest_machine', default='', type=str, help='The domain name or ip address of the destination database machine')
@click.option('--r', '--rename', default='', type=str, help='Renamed on the destination machine')
@click.option('-v', '--verbosity', count=True, callback=set_verbosity, expose_value=False, is_eager=True)
@click.pass_obj
def sites_db_copy(config, database, source_machine, dest_machine, rename):
    if not any([database, source_machine, dest_machine, rename]):
        click.echo(config.sites_list())

    if not database:
        database = prompt('Database', type=str)
    if not source_machine:
        click.echo(config.machines_list())
        source_machine = prompt('Source machine', type=str)
    if not dest_machine:
        click.echo(config.machines_list())
        dest_machine = prompt('Destination machine', type=str)
    if not rename:
        rename = prompt('Database name on destination machine', type=str)

    # rename contains the list of dest_databases to be renamed.
    dest_databases = rename
    config.db_copy(database, source_machine, dest_machine, dest_databases)

@sites.command("asset_sync", help='Sync a file or directory')
@click.option('--asset', default='', type=str, help='The asset to copy')
@click.option('--source_machine', default='', type=str, help='The domain name or ip address of the source database machine')
@click.option('--dest_machine', default='', type=str, help='The domain name or ip address of the destination database machine')
@click.option('--destination', default='', type=str, help='The location to put the asset on the destination machine')
@click.option('-v', '--verbosity', count=True, callback=set_verbosity, expose_value=False, is_eager=True)
@click.pass_obj
def sites_asset_sync(config, asset, source_machine, dest_machine, destination):
    if not asset:
        asset = prompt('Asset Path', type=str)

    if not any([source_machine, dest_machine]):
        click.echo(config.machines_list())

    if not source_machine:
        click.echo(config.machines_list())
        source_machine = prompt('Source machine', type=str)
    if not dest_machine:
        click.echo(config.machines_list())
        dest_machine = prompt('Destination machine', type=str)
    if not destination:
        destination = prompt('Destination asset path', type=str)

    config.asset_sync(asset, source_machine, dest_machine, destination, True, False)

@sites.command("checkout", help='Check out a Gitlab Project')
@click.option('--project_id', default='', type=str, help='The Gitlab Project_ID to checkout')
@click.option('--branch', default='', type=str, help='Branch in Gitlab to checkout')
@click.option('-v', '--verbosity', count=True, callback=set_verbosity, expose_value=False, is_eager=True)
@click.pass_obj
def sites_checkout(config, project_id, branch):
    if not project_id:
        click.echo(config.sites_list())
        project_id = prompt('Project ID', type=str)
    if not branch:
        config.checkout(project_id)
    else:
        config.checkout(project_id, branch)

@sites.command("merge_branches", help='Merge two branches in a Gitlab Project')
@click.option('--project_url', default='', type=str, help='The Gitlab Project_ID to merge')
@click.option('--source_branch', default='', type=str, help='The branch to be merged')
@click.option('--dest_branch', default='', type=str, help='The branch to be merged into')
@click.option('-v', '--verbosity', count=True, callback=set_verbosity, expose_value=False, is_eager=True)
@click.pass_obj
def sites_merge(config, project_url, source_branch, dest_branch):
    if not config.sites_exist():
        error('No sites exists!')
        return

    if not any([project_url, source_branch, dest_branch]):
        click.echo(config.sites_list())

    if not project_url:
        project_url = prompt('Repository URL or Domain', type=str)
    if not source_branch:
        source_branch = prompt('Source branch', type=str)
    if not dest_branch:
        dest_branch = prompt('Destination branch', type=str)

    config.merge(project_url, source_branch, dest_branch)

@cli.group(invoke_without_command=True, help='List or modify environments')
@click.pass_context
def envs(ctx):
    if not ctx.args:
        ctx.invoke(envs_interactive)

@envs.command('interactive', help='Manage environments in interactive mode')
@click.pass_context
def envs_interactive(ctx, from_main_menu=False):
    if from_main_menu:
        exit_term = 'Back'
    else:
        exit_term = 'Exit'

    click.clear()
    while True:
        click.echo('Environment operations:')
        click.echo('[0] %s' % exit_term)
        click.echo('[1] %s' % envs_list.short_help)
        click.echo('[2] %s' % envs_add.short_help)
        click.echo('[3] %s' % envs_edit.short_help)
        click.echo('[4] %s' % envs_delete.short_help)

        try:
            value = prompt("Option", type=int)

            if value == 0:
                break
            elif value == 1:
                ctx.invoke(envs_list)
            elif value == 2:
                ctx.invoke(envs_add)
            elif value == 3:
                ctx.invoke(envs_edit)
            elif value == 4:
                ctx.invoke(envs_delete)
            else:
                warn('Option not available')
        except Abort as e:
            click.secho('Aborting...\n', fg="red")

@envs.command('edit', help='Edit an environment')
@click.argument('env', required=False)
@click.pass_context
def envs_edit(ctx, env):
    env = env_prompt(ctx.obj, env, 'Enter name of environment to edit')

    if confirm_prompt('Do you want to change the title?'):
        ctx.invoke(edit_env_title, env=env)

    while confirm_prompt('Do you want to checkout code to an additional machine?'):
        ctx.invoke(add_vcs_machine, env=env)
    
    while confirm_prompt('Do you no longer want to check out code to a machine?'):
        ctx.invoke(delete_vcs_machine, env=env)

    if ctx.obj.env_has_dbs(env):
        if confirm_prompt('Do you want to disconnect the current database machine from this environment?'):
            ctx.invoke(delete_db_machine, env=env)
    
    if not ctx.obj.env_has_dbs(env):
        if confirm_prompt('Do you want to add a database machine to this environment?'):
            ctx.invoke(add_db_machine, env=env)

@envs.command('list', help='List of environments')
@click.pass_obj
def envs_list(config):
    click.echo(config.envs_list())

@envs.command('add', help='Add a new environment')
@click.option('--name', default='', type=str, help='Environment to add, eg staging or specialdev')
@click.option('--title', default='', type=str, help='Title of environment to add, eg Development')
@click.pass_obj
def envs_add(config, name, title):
    def name_prompt():
        name = None
        while not name:
            click.echo(config.envs_list())
            name_check = prompt('Name of environment (eg. staging or specialdev)', type=str)
            if not config.env_exists(name_check):
                name = name_check
            else:
                warn('Environment already exists')
        return name
    if not name:
        name = name_prompt()
    elif config.env_exists(name):
        warn('Environment already exists')
        name = name_prompt()

    if not title:
        title = prompt('Title of environment (eg. Staging or Development)', type=str)


    name = env_standardize(config, name)

    config.envs_add(name, title)

    if not config.machines_exist():
        if confirm_prompt('No machines exist! Would you like to add a machine now?'):
            prompts = _machines_add_prompts(config, '', '', '', '', '')
            config.machines_add(prompts['name'], 
                                prompts['title'], 
                                prompts['description'], 
                                prompts['fqdn'], 
                                prompts['ip'], 
                                prompts['services'])
            if confirm_prompt('Should code be deployed on this machine for this environment?'):
                git_deploy_machine = prompts['name']
        else:
            return
    else:
        click.echo(config.machines_list())
        git_deploy_machine = None
        while not git_deploy_machine:
            click.echo('What is the first (or only) machine the code should be deployed on for this environment?')
            git_deploy_machine_check = prompt('Name of machine', type=str)
            if config.machine_exists(git_deploy_machine_check):
                git_deploy_machine = git_deploy_machine_check
            else:
                warn('Machine does not exist!')

    web_root = prompt('Where should the code be deployed?', type=str, default="/var/www/cascade/%s" % name)

    config.add_vcs_machine(name, git_deploy_machine, web_root)

    while True:
        add_another = confirm_prompt('Do you want this environment to deploy code to another machine?')

        if add_another :
            # TODO: allow user to enter both name or select from list
            git_deploy_machine = prompt('Machine name', type=str)
            prompt('Where should the code be deployed?', type=str, default="/var/www/cascade/%s" % git_deploy_machine)
            config.add_vcs_machine(name, git_deploy_machine, web_root)
        else:
            break

    if confirm_prompt('Do sites in this environment connect to a database?'):
        click.echo(config.machines_list())
        # TODO: allow user to enter both by name or select from list
        db_machine = None
        while not db_machine:
            db_machine_check = prompt('Machine that has the database', type=str)
            if config.machine_exists(db_machine_check):
                db_machine = db_machine_check
            else:
                warn('Machine does not exist!')

        if db_machine:
            config.add_db_machine(name, db_machine)

    click.echo('Environment successfully added.')

@envs.command('edit_title', help='Edit environment title')
@click.argument('env', required=False)
@click.option('--title', default='', type=str, help='New title for environment')
@click.pass_obj
def edit_env_title(config, env, title):
    env = env_prompt(config, env, 'Enter name of environment to change title')

    if not title:
        title = prompt('New title', type=str)

    config.envs_edit_title(env, title)

@envs.command('delete', help='Delete an environment')
@click.argument('env', required=False)
@click.option('-f', '--force', is_flag=True)
@click.pass_obj
def envs_delete(config, env, force):
    env = env_prompt(config, env, 'Enter name of environment to delete')

    if force:
        info('Issuing a forced delete...')
        config.envs_delete(env)
    else:
        if confirm_prompt("Are you sure you want to delete environment '%s'?" % env):
            config.envs_delete(env)

@envs.command(help='Add a Version Control System checkout to an environment')
@click.argument('env', required=False)
@click.option('--machine', default='', type=str, help='Machine to add webroot to, eg XXXelmp01')
@click.option('--webroot', default='', type=str, help='Directory to deploy to, eg /var/www/cascade/dev')
@click.pass_obj
def add_vcs_machine(config, env, machine, webroot):
    env = env_prompt(config, env, 'Enter name of environment to add VCS machine to')

    if not machine:
        click.echo(config.machines_list())
        
        # Do the same for a valid machine.
        while not machine:
            machine_check = prompt('Machine to add webroot to (eg. XXXelmp01)', type=str)
            if config.machine_exists(machine_check):
               machine = machine_check
            else:
               warn('Machine does not exist!')

    if not webroot:
        webroot = prompt('Web root, the directory to deploy to', type=str, default="/var/www/cascade/%s" % env_standardize(config, env))

    config.add_vcs_machine(env, machine, webroot)

@envs.command(help='Delete the VCS machine of an environment')
@click.argument('env', required=False)
@click.argument('machine', required=False)
@click.pass_obj
def delete_vcs_machine(config, env, machine):
    env = env_prompt(config, env, 'Enter name of environment to remove VCS machine from')

    if not machine:
        click.echo(config.envs_list())
        while not machine:
            machine_check = prompt('Enter VCS machine to edit', type=str)
            if config.vcs_machine_exists(env, machine_check):
                machine = machine_check
            else:
                warn("Machine does not exist!")

    config.delete_vcs_machine(env, machine)

@envs.command('databases', help='List all databases')
@click.argument('env', required=False)
@click.pass_obj
def envs_databases(config, env):
    env = env_prompt(config, env, 'Enter name of environment to show databases')
    config.envs_databases(env)

@envs.command(help='Add a database to an environment')
@click.argument('env', required=False)
@click.option('--machine', default='', type=str, help='Database server, eg XXXeldb01')
@click.pass_obj
def add_db_machine(config, env, machine):
    env = env_prompt(config, env, 'Enter name of environment to add DB machine to')
    if not machine:
        click.echo(config.machines_list())
        while not machine:
            machine = prompt('Machine that has the database', type=str)

    config.add_db_machine(env, machine)

@envs.command(help='Delete the DB machine of an environment')
@click.argument('env', required=False)
@click.argument('machine', required=False)
@click.pass_obj
def delete_db_machine(config, env, machine):
    env = env_prompt(config, env, 'Enter name of environment to remove DB machine from')

    if not machine:
        click.echo(config.machines_list())
        while not machine:
            machine_check = prompt('Enter name of DB machine', type=str)
            if config.db_machine_exists(env, machine_check):
                machine = machine_check 
            else:
                warn("Machine does not exist!")

    config.delete_db_machine(env, machine)

@cli.group(invoke_without_command=True, help='List, modify, and perform actions on services.')
@click.pass_context
def services(ctx):
    if not ctx.args:
       ctx.invoke(services_interactive)

@services.command('interactive', help='Manage services in interactive mode')
@click.pass_context
def services_interactive(ctx, from_main_menu=False):
    if from_main_menu:
        exit_term = 'Back'
    else:
        exit_term = 'Exit'

    click.clear()
    while True:
        click.echo('[0] %s' % exit_term)
        click.echo('[1] %s' % services_list.short_help)
        click.echo('[2] %s' % services_add.short_help)
        click.echo('[3] %s' % services_delete.short_help)

        try:
            value = prompt("Option", type=int)

            if value == 0:
                break
            elif value == 1:
                ctx.invoke(services_list)
            elif value == 2:
                ctx.invoke(services_add)
            elif value == 3:
                ctx.invoke(services_delete)
            else:
                click(warn, 'Option not available')
        except Abort as e:
            click.secho('Aborting...\n', fg="red")

@services.command('list', help='List services for all or a particular machine')
@click.option('--machine', default='', type=str, help='Machine on which to list the services')
@click.pass_obj
def services_list(config, machine):
    click.echo(config.services_list(machine))

@services.command('add', help='Add a service to Cascade to restart')
@click.option('--name', default='', type=str, help='eg: Apache')
@click.option('--machine', default='', type=str, help='Machine to add service to, eg XXXelmp01')
@click.option('--service', default='', type=str, help='The actual service, eg httpd')
@click.pass_obj
def services_add(config, name, machine, service):
    if not machine:
        click.echo(config.machines_list())
        machine = prompt('Machine to add service to (eg XXXelmp01)', type=str)
    if not name:
        name = prompt('Name of service to add (eg. Apache)', type=str)
    if not service:
        service = prompt('Service system name (eg. httpd)', type=str)

    config.services_add(name, machine, service)

@services.command('delete', help='Delete a service from a machine')
@click.option('--name', default='', type=str, help='eg: Apache')
@click.option('--machine', default='', type=str, help='Machine to add service to, eg XXXelmp01')
@click.pass_obj
def services_delete(config, name, machine):
    if not machine:
        click.echo(config.machines_list())
        machine = prompt('Machine to add service to (eg XXXelmp01)', type=str)
    if not name:
        name = prompt('Name of service to add (eg. Apache)', type=str)
    if not service:
        service = prompt('Service system name (eg. httpd)', type=str)

    config.services_delete(name, machine, service)

@cli.group(invoke_without_command=True, help='List or modify machines')
@click.pass_context
def machines(ctx):
    if not ctx.args:
        ctx.invoke(machines_interactive)

@machines.command('interactive', help='Manage machines in interactive mode')
@click.pass_context
def machines_interactive(ctx, from_main_menu=False):
    if from_main_menu:
        exit_term = 'Back'
    else:
        exit_term = 'Exit'

    click.clear()
    while True:
        click.echo('[0] %s' % exit_term)
        click.echo('[1] %s' % machines_list.short_help)
        click.echo('[2] %s' % machines_add.short_help)
        click.echo('[3] %s' % machines_edit.short_help)
        click.echo('[4] %s' % machines_delete.short_help)
        click.echo('[5] %s' % machines_restart.short_help)

        try:
            value = prompt('Option', type=int)

            if value == 0:
                break
            elif value == 1:
                ctx.invoke(machines_list)
            elif value == 2:
                ctx.invoke(machines_add)
            elif value == 3:
                ctx.invoke(machines_edit)
            elif value == 4:
                ctx.invoke(machines_delete)
            elif value == 5:
                ctx.invoke(machines_restart)
            else:
                warn('Option not available')
        except Abort as e:
            click.secho('Aborting...\n', fg="red")

@machines.command('list', help='List current machines')
@click.pass_obj
def machines_list(config):
    click.echo(config.machines_list())

def _machines_add_prompts(config, name, title, description, fqdn, ip):
    if not name:
        click.echo(config.machines_list())

    url = ""

    # Keep prompting for a valid machine name.
    while not name and not fqdn:
        while not fqdn:
            fqdn = prompt('FQDN (Fully Qualified Domain Name, eg. XXXelmp01.example.com)', type=str)

        name_check = prompt('"Machine Name" of machine"', type=str, default=fqdn.partition(".")[0])
        if config.machine_exists(name_check):
            warn("Machine '%s' already exists" % name_check)
        else:
            name = name_check
    if config.machine_exists(name):
        warn("Machine '%s' already exists" % name)
        return

    while not ip:
        try:
            ip = socket.gethostbyname(fqdn) 
        except Exception as e:
            ip = prompt('IPV4 of %s' % fqdn, type=str)

    while not title:
        title = prompt('Title (eg. Development Machine)', type=str)
    while not description:
        description = prompt('Description (eg. Virtual 2X4 with 4GB RAM)', type=str)
    
    services = []
    if confirm_prompt('Will users be able to restart services on this machine?'):
        while True:
            service = {}
            service['service'] = prompt('Service to restart (eg. mysqld)', type=str)

            services.append(service)

            if not confirm_prompt('Add another service?'):
                break
    
    return {
        'name': name,
        'title': title,
        'description': description,
        'fqdn': fqdn,
        'ip': ip,
        'services': services
    }

@machines.command('add', help='Add a machine')
@click.option('--name', default='', type=str, help='Machine to add as an alphanumeric string, eg XXXelmp01')
@click.option('--title', default='', type=str, help='Title, eg: Development Machine')
@click.option('--description', default='', type=str, help='The description of the machine, eg: Virtual 2X4 with 4GB RAM')
@click.option('--fqdn', default='', type=str, help='Fully qualified domain name, eg XXXelmp01.example.com')
@click.option('--ip', default='', type=str, help='The IPV4 of the machine')
@click.pass_obj
def machines_add(config, name, title, description, fqdn, ip):
    prompts = _machines_add_prompts(config, name, title, description, fqdn, ip)
    config.machines_add(prompts['name'], 
                        prompts['title'], 
                        prompts['description'], 
                        prompts['fqdn'], 
                        prompts['ip'], 
                        prompts['services'])

@machines.command('edit', help='Edit a machine')
@click.argument('key', required=False)
@click.option('--title', default='', type=str, help='Title, eg: Development Machine')
@click.option('--description', default='', type=str, help='The description of the machine, eg: Virtual 2X4 with 4GB RAM')
@click.option('--fqdn', default='', type=str, help='Fully qualified domain name, eg XXXelmp01.example.com')
@click.option('--ip', default='', type=str, help='The IPV4 of the machine')
@click.pass_obj
def machines_edit(config, key, title, description, fqdn, ip):
    # if no key, prompt for one, cycle through until we have a valid machine
    if not config.machines_exist():
        warn('No machines exist!')
        return

    if not key:
        click.echo(config.machines_list())
    
        # Keep prompting for a valid env.
        while not key:
            key_check = prompt('Enter name of machine to edit', type=str)
            if config.machine_exists(key_check):
                key = key_check
            else:
                warn("Machine '%s' does not exist" % key_check)
    elif not config.machine_exists(key):
        warn("Machine '%s' does not exist" % key)

    edits = {}

    if not title:
        if confirm_prompt('Change title?'):
            title = prompt('New title', type=str)
            edits['name'] = title
    else:
        edits['name'] = title

    if not description:
        if confirm_prompt('Change description?'):
            description = prompt('New description', type=str)
            edits['description'] = description
    else:
        edits['description'] = description

    if not fqdn:
        if confirm_prompt('Change FQDN (fully qualified domain name)?'):
            fqdn = prompt('New FQDN', type=str)
            edits['fqdn'] = fqdn
    else:
        edits['fqdn'] = fqdn

    if not ip:
        if confirm_prompt('Change IP address?'):
            ip = prompt('New IP', type=str)
            edits['ip'] = ip
    else:
        edits['ip'] = ip

    config.machines_edit(key, edits)
    try:
      if confirm_prompt('Would you like to add services?'):
        service_bin = prompt('Name of service? (eg. mysqld)')
        config.services_add(key, service_bin)

        while True:
            if confirm_prompt('Add another service?'):
                service_bin = prompt('Name of service? (eg. mysqld)')
                config.services_add(key, service_bin)
            else:
                break

      if confirm_prompt('Would you like to remove services?'):

        while True:
            service_bin = prompt('Name of service to remove')
            config.services_delete(service_bin, key)
            if not confirm_prompt('Remove another service?'):
                break
    except Exception as e:
      error(e)
      exit

@machines.command('delete', help='Delete a machine')
@click.argument('key', required=False)
@click.option('-f', '--force', is_flag=True)
@click.pass_obj
def machines_delete(config, key, force):
    if not config.machines_exist():
        warn('No machines exist!')
        return

    if not key:
        click.echo(config.machines_list())
        
        # Keep prompting for a valid env.
        while not key:
            key_check = prompt('Enter machine to delete', type=str)
            if config.machine_exists(key_check):
                key = key_check
            else:
                warn('Machine does not exist!')
    elif not config.machine_exists(key):
        warn("Machine '%s' does not exist!" % key)
        return

    confirm = False
    if force:
        confirm = True
    else:
        if confirm_prompt("Are you sure you want to delete machine '%s'?" % key):
            confirm = True

    if confirm:
        if config.machines_delete(key):
            click.echo('Machine successfully deleted')
        else:
            warn('Failed to delete machine')

@machines.command('restart_service', help='Restart a service')
@click.option('--service', default='', type=str, help='The service to restart on the remotes')
@click.option('--machines', default='', type=str, help='A list of domain names or ip addresses')
@click.option('-v', '--verbosity', count=True, callback=set_verbosity, expose_value=False, is_eager=True)
@click.pass_obj
def machines_restart(config, service, machines):
    if not config.machines_exist():
        error('No machines exists!')
        return

    if not machines:
        click.echo(config.machines_list())
        machines = prompt('Machine to restart', type=str)
    if not service:
        click.echo(config.services_list())
        service = prompt('Service to restart', type=str)

    config.restart(service, machines)

@cli.group(invoke_without_command=True, help='List or modify groups')
@click.pass_context
def groups(ctx):
    if not ctx.args:
        ctx.invoke(groups_interactive)

@groups.command('interactive', help='Manage groups in interactive mode')
@click.pass_context
def groups_interactive(ctx, from_main_menu=False):
    if from_main_menu:
        exit_term = 'Back'
    else:
        exit_term = 'Exit'

    click.clear()
    while True:
        click.echo('[0] %s' % exit_term)
        click.echo('[1] %s' % groups_list.short_help)
        click.echo('[2] %s' % groups_add.short_help)
        click.echo('[3] %s' % groups_delete.short_help)

        try:
            value = prompt("Option", type=int)

            if value == 0:
                break
            elif value == 1:
                ctx.invoke(groups_list)
            elif value == 2:
                ctx.invoke(groups_add)
            elif value == 3:
                ctx.invoke(groups_delete)
            else:
                warn('Option not available')
        except Abort as e:
            click.secho('Aborting...\n', fg="red")

@groups.command('list', help='List groups')
@click.pass_obj
def groups_list(config):
    click.echo(config.groups_list())
    
@groups.command('add', help='Add a group to Cascade and Gitlab')
@click.option('--name', default='', type=str, help='Group to add as an alphanumeric string')
@click.pass_obj
def groups_add(config, name):
    if not name:
        click.echo(config.groups_list())

        # Keep prompting for a valid group.
        while not name:
            name_check = config.sanitize(prompt('Group name to add', type=str), "-")
            if not config.group_exists(name_check):
                name = name_check
            else:
                warn("Group '%s' already exists" % name_check)
    elif config.group_exists(name):
        warn("Group '%s' already exists" % name_check)
        return

    config.groups_add(name)

@groups.command('edit-notes', help="Edit a Group's notes")
@click.argument('name', required=False)
@click.option('--notes', default='', type=str, help='New notes for the Group')
@click.pass_obj
def groups_edit_notes(config, name, notes):
    if not name:
        if config.groups_exist():
            click.echo(config.groups_list())
        else:
            warn('No groups exist!')
            return

        # Keep prompting for a valid group.
        while not name:
            name_check = prompt('Enter name of group to delete', type=str)
            if config.group_exists(name_check):
                name = name_check
            else:
                warn('Group does not exist!')
    elif not config.group_exists(name):
        warn('Group does not exist!')
        return

    if not notes:
        notes = prompt('New notes', type=str)

    config.groups_edit_notes(name, notes)

@groups.command('delete', help='Delete a group')
@click.argument('name', required=False)
@click.option('-f', '--force', is_flag=True)
@click.pass_obj
def groups_delete(config, name, force):
    if not name:
        if config.groups_exist():
            click.echo(config.groups_list())
        else:
            warn('No groups exist!')
            return

        # Keep prompting for a valid group.
        while not name:
            name_check = prompt('Enter name of group to delete', type=str)
            if config.group_exists(name_check):
                name = name_check
            else:
                warn('Group does not exist!')
    elif not config.group_exists(name):
        warn('Group does not exist!')
        return

    if force:
        debug('Issuing a force delete...')
        config.groups_delete(name)
    else:
        if confirm_prompt("Are you sure you want to delete group '%s'?" % name):
            config.groups_delete(name)
