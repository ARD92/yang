# Unicast vxlan support on cRPD

To install the package, copy the files into cRPD


## Start cRPD 
Note: *Currently the hostname and container name should be the same, else MQTT may not start*
```
docker volume create crpd01-vardb
docker volume create crpd01-config
docker volume create crpd01-varlog
docker run -itd --privileged --name crpd01 -h crpd01 -v crpd01-config:/config -v crpd01-vardb:/var/db -v crpd01-varlog:/var/log crpd:latest  
```

## Copy package into cRPD 
```
docker cp unicast-vxlan crpd01:/home
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
- currently you cannot modify an existing tunnel. you will have to delete the tunnel and re-create it. i.e. Replace pattern statements are not handled.
    - delete the tunnel interface
    - commit
    - create the new tunnel interface
    in case you miss the commit in the second step, it is similar to replace pattern where mgd handles it as a replace operation and that is not handled, hence the     commit in step 2 is important.

## WIP 
- Need to use native netlink APIs to create interfaces
- support for IPv6

## Debugging 
- monitor the logs at /var/log/unicast-vxlan.log. If log rotation details need to be changed. The respective params must be changed in the unicast-vxlan.py file 
- For every interface created, it is tracked under /var/db/INTF-STORE.json. If the value doesnt exist here and yet the vxlan interface is remaining, there would be an instability and would need to check the log file accordingly
- monitor if the service is up and running 
    ```
    root@crpd01:/# sv status unicast-vxlan
    run: unicast-vxlan: (pid 928) 12476s
    ```
    To restart 
    ```
    root@crpd01:/# sv restart unicast-vxlan
    ok: run: unicast-vxlan: (pid 966) 0s
    ```
    check the process
    ```
    root@crpd01:/# ps aux | grep unicast-vxlan
    root         812  0.0  0.0   4412  1192 ?        Ss   10:04   0:00 runsv unicast-vxlan
    root         966  0.1  0.0  81100 23344 ?        S    14:39   0:00 python3 /var/db/scripts/jet/unicast-vxlan.py
    root         970  0.0  0.0  11476  1004 pts/3    S+   14:40   0:00 grep --color=auto unicast-vxlan
    ```
- monitor MQTT and ui-pubd process. Ensure they are up
    ```
    root@crpd01:/# ps aux | grep mosquitto
    103          766  1.3  0.0  53936 14468 pts/1    S    10:04   3:41 /usr/sbin/mosquitto -c /etc/mosquitto/mosquitto.conf
    root         974  0.0  0.0  11476  1012 pts/3    S+   14:41   0:00 grep --color=auto mosquitto

    root@crpd01:/# ps aux | grep ui-pubd
    root         767  0.0  0.0 787124 17172 pts/1    S    10:04   0:00 /usr/libexec/ui-pubd -N
    root         976  0.0  0.0  11476  1096 pts/3    S+   14:41   0:00 grep --color=auto ui-pubd
    ```
