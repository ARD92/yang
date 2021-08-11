# Unicast vxlan support on cRPD

To install the package, copy the files into cRPD

```
docker cp unicast-vxlan <crpd container>:/home
```
you can also mount the volume into /var/db directory to ensure all the files are intact. 

## configure cRPD

The below configuration needs to be configured first 

```
set system commit xpath
set system commit constraints direct-access
set system commit notification configuration-diff-format xml
set system scripts language python3
```

## Install the package using

```
sh install-package.sh
```

## Configure unicast vxlan tunnels on cRPD with the newly introduced hierarchy

```
set unicast-vxlan:vxlan interface vxlan108 interface node1_node2
set unicast-vxlan:vxlan interface vxlan108 ip-prefix 18.1.1.1/30
set unicast-vxlan:vxlan interface vxlan108 remote-ip 192.168.1.2
set unicast-vxlan:vxlan interface vxlan108 destination-port 8479
set unicast-vxlan:vxlan interface vxlan108 vni 108
```

### Validate the configuration

```
root@node1# show | compare
[edit]
+  unicast-vxlan:vxlan {
+      interface vxlan108 {
+          interface node1_node2;
+          ip-prefix 18.1.1.1/30;
+          remote-ip 192.168.1.2;
+          destination-port 8479;
+          vni 108;
+      }
+  }

root@node1# commit
commit complete
```

### check interface states
```
root@node1# run show interfaces routing
Interface        State Addresses
vxlan108         Up    ISO   enabled
                       MPLS  enabled
                       INET  18.1.1.1
                       INET6 fe80::e849:3bff:fedc:a00c
```

## Caveats
- currently only IPv4 interfaces are supported
- if protocols which need to leverage this vxlan tunnel needs to be used, we would need to create vxlan intf first. i.e
    - create vxlan config
    - commit
    - config rest of the protocols using vxlan intf
    - commit 

## WIP 
- Need to daemonize the script using init.d 
- Need to use native netlink APIs to create interfaces
