<template>
  <div id="app">
    <v-shell
      :banner="banner"
      :shell_input="send_to_terminal"
      :commands="commands"
      @shell_output="prompt"
    ></v-shell>
  </div>
</template>

<script>
export default {
  name: "App",
  data() {
    return {
      send_to_terminal: "",
      banner: {
        header: "E-Corp Shell",
        helpHeader: 'Enter "help" for more information.',
        emoji: {
          first: "base"
        },
        sign: `Henry@Ecorp:~#`,
        img: {
          align: "left",
          link:
            "https://www.e-corp-usa.com/images/home-v2/ecorp_logo_white.png",
          width: 60,
          height: 80
        },
        pwd: "",
        dir_parent: " ",
        dir: "/home/henry"
      },
      commands: [
        {
          name: "uname",
          get() {
            return navigator.appVersion;
          }
        },
        {
          name: "sudo",
          get() {
            return `<p style="color:red;">[ERROR] You are not in the sudoers file. This incident will be reported</p>`;
          }
        },
        {
          name: "ifconfig",
          get() {
            return `  enp2s0: flags=4163&lt;UP,BROADCAST,RUNNING,MULTICAST&gt;  mtu 1500
          inet 192.168.1.106  netmask 255.255.255.0  broadcast 192.168.0.255
          inet6 fe80::8e29:fe4b:875d:213d  prefixlen 64  scopeid 0x20&lt;link&gt;
          ether 20:89:84:90:2b:cd  txqueuelen 1000  (Ethernet)
          RX packets 8350  bytes 11271255 (11.2 MB)
          RX errors 0  dropped 0  overruns 0  frame 0
          TX packets 5336  bytes 474287 (474.2 KB)
          TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

  lo: flags=73&lt;UP,LOOPBACK,RUNNING&gt;  mtu 65536
          inet 127.0.0.1  netmask 255.0.0.0
          inet6 ::1  prefixlen 128  scopeid 0x10&lt;host&gt;
          loop  txqueuelen 1000  (Локальная петля (Loopback))
          RX packets 518  bytes 40060 (40.0 KB)
          RX errors 0  dropped 0  overruns 0  frame 0
          TX packets 518  bytes 40060 (40.0 KB)
          TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

  wlp3s0: flags=4099&lt;UP,BROADCAST,MULTICAST&gt;  mtu 1500
          ether 60:6c:66:b3:90:8e  txqueuelen 1000  (Ethernet)
          RX packets 0  bytes 0 (0.0 B)
          RX errors 0  dropped 0  overruns 0  frame 0
          TX packets 0  bytes 0 (0.0 B)
          TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0`;
          }
        }
      ]
    };
  },
  methods: {
    prompt(value) {
      if (value.trim().toLowerCase() === "test_temp_dir") {
        this.send_to_terminal = this.$data.dir
          .split("\\")
          .pop()
          .split("/")
          .pop();
      } else if (value.trim().toLowerCase() === "test_par_dir") {
        this.send_to_terminal = this.$data.dir.slice(
          0,
          this.$data.dir.lastIndexOf("/")
        );
      } else if (value.trim().toLowerCase() === "cd data") {
        this.$data.banner.sign = "Henry@Ecorp:/~Data#";
      } else if (value.trim().toLowerCase() === "cd") {
        this.$data.banner.sign = "Henry@Ecorp:~#";
        this.$data.dir = "/home/henry";
      } else if (value.trim().toLowerCase() === "ls") {
        if (this.$data.banner.sign.slice(-5).toLowerCase() === "data#") {
          this.$data.dir = "/home/henry/Data/";
          this.send_to_terminal = "Data_Files.dat";
        } else {
          this.send_to_terminal = `<table class="table" style="width:70%; margin-top: 5px;">
              <tr>
                <td><p>efhuiu3rh37d.dat</p></td>
                <td><p style="color:#838383;">Applications</p></td>
                <td><p style="color:#838383;">Library</p></td>
              </tr>
              <tr>
                <td>printers.xml</td>
                <td><p style="color:#838383;">Data</p></td>
                <td><p>d_rsa.pub</p></td>
              </tr>
            </table>`;
        }
      } else if (value.trim().toLowerCase() === "pwd") {
        this.send_to_terminal = "PWD_EX";
      } else if (value.trim().toLowerCase() === "main_test") {
        this.send_to_terminal = `<table class="table" style="width:70%; margin-top: 5px;">
    <tr>
        <td><p style="color:green;">bin</p></td>
        <td><p style="color:#838383;">dev</p></td>
        <td><p style="color:green;">lib</p></td>
        <td><p style="color:green;">libx32</p></td>
        <td><p style="color:#838383;">mnt</p></td>
        <td><p style="color:#838383;">root</p></td>
        <td><p style="color:#838383;">snap</p></td>
        <td bgcolor=green><p style="color:#151515;">tmp</p></td>
    </tr>
    <tr>
        <td><p style="color:#838383;">boot</p></td>
        <td><p style="color:#838383;">etc</p></td>
        <td><p style="color:green;">lib32</p></td>
        <td><p style="color:#838383;">lost+found</p></td>
        <td><p style="color:#838383;">opt</p></td>
        <td><p style="color:#838383;">run</p></td>
        <td><p style="color:#838383;">srv</p></td>
        <td><p style="color:#838383;">usr</p></td>
    </tr>
    <tr>
        <td><p style="color:#838383;">cdrom</p></td>
        <td><p style="color:#838383;">home</p></td>
        <td><p style="color:green;">lib64</p></td>
        <td><p style="color:#838383;">media</p></td>
        <td><p style="color:#838383;">proc</p></td>
        <td><p style="color:green;">sbin</p></td>
        <td><p style="color:#838383;">sys</p></td>
        <td><p style="color:#838383;">var</p></td>
    </tr>
</table>`;
      } else {
        this.send_to_terminal = `'${value}' is not recognized as an internal command or external,
an executable program or a batch file`;
      }
    }
  }
};
</script>

<style>
</style>