# Unicast vxlan support on cRPD

To instal the package, copy the files into cRPD

```
docker cp unicast-vxlan <crpd container>:/home
```

## configure cRPD

The below configuration needs to be configured first 

```
set system commit xpath
set system commit constraints direct-access
set system commit notification configuration-diff-format xml
set system scripts language python3

set system services extension-service request-response grpc clear-text address 0.0.0.0
set system services extension-service request-response grpc clear-text port 50051
set system services extension-service request-response grpc max-connections 8
set system services extension-service notification port 1883
set system services extension-service notification allow-clients address 0.0.0.0/0
```

## Install the package using

```
sh install-package.sh
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
