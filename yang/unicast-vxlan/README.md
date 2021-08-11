# Unicast vxlan support on cRPD

To instal the package, copy the files into cRPD

```
docker cp unicast-vxlan <crpd container>:/home
```
Install the package using

```
sh install-package.sh
```

## configure cRPD 
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

## Caveats and WIP
- currently only IPv4 interfaces are supported
- Need to use native netlink APIs to create interfaces 
