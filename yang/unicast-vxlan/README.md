# Unicast vxlan support on cRPD

To instal the package, copy the files into cRPD

```
docker cp unicast-vxlan <crpd container>:/home
```
Install the package using

```
install-package.sh
```
## Caveats and WIP
- currently only IPv4 interfaces are supported
- Need to use native netlink APIs to create interfaces 
