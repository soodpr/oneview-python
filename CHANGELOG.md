# 5.0.0
#### Notes
Extends support of the SDK to OneView REST API version 800 (OneView v4.10).

#### Major changes
 1. Extending support of SDK to API version 800.
 2. Refactored base classes to keep the resource data with the resource object.
    This will help to write more helper methods for the resources.
 3. Introduced mixin classes to include the optional features of the resources.

#### Breaking
  Enhancement made in this version breaks the previous version of the SDK.
  From this version onwards, resource object should be created to call a resource method.

  E.g.
       oneview_client = OneViewClient(config)
       fc_networks = oneview_client.fc_networks

       fc_network = fc_networks.get_by_name(name) / create # Get an existing FCNetwork's object by it's name or create one
       fc_network.update(update_data)                      # Update FCNetwork
       fc_network.delete()                                 # Delete FCNetwork

  Refer example directory for more examples.

#### Features supported with current release
- Connection template
- Enclosure
- Enclosure group
- Ethernet network
- FC network
- FCOE network
- Interconnect type
- Internal link set
- Logical enclosure
- Logical interconnect
- Logical interconnect group
- Logical switch group
- Managed SAN
- OS deployment plan
- SAS interconnect
- SAS interconnect type
- SAS logical interconnect
- SAS logical interconnect group
- Server hardware
- Server hardware type
- Server profile
- Server profile template
- Switch type
- Uplink set
