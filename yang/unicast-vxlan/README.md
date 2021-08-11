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
```

## Caveats and WIP
- currently only IPv4 interfaces are supported
- Need to use native netlink APIs to create interfaces 
