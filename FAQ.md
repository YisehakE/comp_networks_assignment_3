# Commonly Experienced Cougarnet Issues - and How to Fix Them

 - "Error creating link `bar`: ovs-vsctl: cannot create a bridge named `foo`
   because a bridged named `foo` already exists"

   Run the following to delete bridge `foo`:
   ```bash
   $ sudo ovs-vsctl del-br foo
   ```
 - "Error creating link `foo`: RTNETLINK answers: File exists"

   Run the following to delete the link `foo`:
   ```bash
   $ sudo ip link del foo
   ```
   Note that you can list all network devices by running the following:
   ```bash
   $ ip link
   ```
 - "Namespace already exists: /run/netns/foo"

   Run the following to unmount (if necessary) and then delete the namespace
   `foo`:
   ```
   $ sudo umount /run/netns/foo
   $ sudo rm /run/netns/foo
   ```

 - "pkg\_resources.DistributionNotFound: The 'cougarnet==0.0.0' distribution
   was not found and is required by the application"

   Make sure you are building and installing cougarnet from a folder that is
   _outside_ your shared folder (i.e., a folder that is shared between you and
   the host using VirtualBox).  To fix things, do the following:

   1. Clone Cougarnet outside the shared folder.  For example:
      ```
      $ cd ~/
      $ git clone https://github.com/cdeccio/cougarnet
      ```

   2. Enter the directory, and build/install from there:
      ```
      $ cd cougarnet
      $ python3 setup.py build
      $ sudo python3 setup.py install
      ```
      Note that `~/` is the user's home directory, and I wouldn't expect this
      to be a shared folder.

Rebooting the system will some of the issues mentioned above--except the
existence of the Open vSwitch bridge (i.e., the one requiring `ovs-vsctl`).
