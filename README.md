# watts_plugin_opennebula
WaTTS Plugin for OpenNebula, adding dynamically users to OpenNebula.

copy the plugin 'opennebula.py' to your WaTTS plugin folder, usually '/var/lib/watts/plugins'.

The plugin can be enable by adding a few lines to the WaTTS configuration:

```
service.opennebula.description = OpenNebula
# adjust the cmd setting to point to the plugin
service.opennebula.cmd = /var/lib/watts/plugins/opennebula.py
service.opennebula.credential_limit = 2
service.opennebula.connection.type = local
# this allows anyone to use the plugin, please check the WaTTs
# documentation how to limit the access
service.opennebula.authz.allow.any.sub.any = true
# the followin settings set the plugin parameter
# uncomment a line if you want to change the default
# The defaults are listed below
#service.opennebula.plugin.sessionid = oneadmin:somepass
#service.opennebula.plugin.user_group = 105
#service.opennebula.plugin.api_endpoint = http://localhost:2633/RPC2
#service.opennebula.plugin.db_file = /tmp/users.db
#service.opennebula.plugin.user_prefix = watts
```
