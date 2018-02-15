# Python-project

```bash
usage: projectLauncher.py [-h] [--range RANGE_ARG] [--password PWD_ARG]
                          [-f FROM_F]

Retrieves the network topology, all its devices and their interfaces
information

optional arguments:
  -h, --help            show this help message and exit
  --range RANGE_ARG, -r RANGE_ARG
                        Enables to pass the IPs range in a form of W.X.Y.Z#A,
                        eg. 192.168.0.1#10. Preceded by a `-f` flag, it takes
                        a file which should contain IP ranges
  --password PWD_ARG, -p PWD_ARG
                        Takes a password string used as a CommunityString by
                        SNMP. Preceded by a `-f` flag, it takes a file which
                        should contain.If omitted given the flag `--range` one
                        will be prompted for a hidden password.If the given
                        value is empty, the program attempts to acquire a
                        password from the password.txt file in the directory
                        where projectLauncher.py is located.
  -f FROM_F, --file FROM_F
                        Enables to read ranges and passwords values from given
                        files on the CLI.Should be followed by `--range | -r`
                        or `--password | -p` flags

```

The present project is designed to fulfill the requirements stated [here](https://ciscosales.instructure.com/courses/56/assignments/3313?module_item_id=4765)

### Practical Example

#### Topology

 ![Topology.png](https://raw.github.com/MagdaRyb/Python-project/Initial-Commit/static-content/Topology.png)
 
#### Configurations

In order to test the present, one should refer to [the configuration files](https://github.com/MagdaRyb/Python-project/tree/Initial-Commit/static-content)
 or provide  a personalized topology, configs, passwords and range files

#### Python Version

```bash
$ python --version 
Python 2.7.14
```

#### Dependencies to be installed

```bash
$ python -m pip install pysnmp  
$ python -m pip install matplotlib  # Not in use
$ python -m pip install networkx    # Not in use
$ python -m pip install setuptools  
$ python -m pip install colorama    # For styled printing

```

#### How to test 

To test the present, make sure to be connected to the network you would like to query. 
- Setup SNMP on these devices  with a Community String that you will add to the [password.txt](https://raw.github.com/MagdaRyb/Python-project/Initial-Commit/password.txt) file
- Add the range of IPs used in the network in the [range.txt](https://raw.github.com/MagdaRyb/Python-project/Initial-Commit/range.txt) file 
- Execute one of the command given below  
    ```bash
   $ python projectLauncher.py
   $ python projectLauncher.py -f --range /file_location/range_filename --password /file_location/password_filename
   $ python projectLauncher.py -f --range /file_location/range_filename
   Password:
   $ python projectLauncher.py --range 192.168.0.1#25
   Password:
   $ python projectLauncher.py --range 192.168.0.1#25 -f --password /file_location/password_filename
   $ python projectLauncher.py --range 192.168.0.1#25 --password public
    ```

#### What's next?

See the module [documentation](http://htmlpreview.github.com/?https://github.com/MagdaRyb/Python-project/blob/Initial-Commit/static-content/Docs/ciscoIncubatorProjectGroup11.html)