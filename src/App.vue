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

//////////////////////////
// Files Classification
// 0 = file
// 1 = dir
// 2 = specDir
// 3 = tmp
//////////////////////////
// Accesss Classification
// 0 = Accesss Denied
// 1 = Accesss Allowed

<script>
export default {
  name: "App",
  data() {
    return {
      send_to_terminal: "",
      newDir: "",
      newDirName: "",
      tempDirName: "",
      parentDirName: " ",
      dirRootArr: [
        ["bin", "dev", "lib", "libx32", "mnt", "root", "snap", "tmp"],
        ["boot", "etc", "lib32", "lost+found", "opt", "run", "srv", "usr"],
        ["cdrom", "home", "lib64", "tools", "proc", "sbin", "sys", "var"]
      ],
      dirRootClass: [
        [2, 1, 2, 2, 1, 1, 1, 3],
        [1, 1, 2, 1, 1, 1, 1, 1],
        [1, 1, 2, 1, 1, 2, 1, 1]
      ],
      dirRootAcc: [
        [0, 0, 0, 0, 0, 0, 0, 0],
        [0, 0, 0, 0, 0, 0, 0, 0],
        [0, 0, 0, 1, 0, 0, 0, 0]
      ],
      dir: "/home/henry",
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
        }
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
      let td = "";
      //////////////////////////////////////////////////////////////////////////////////////////
      // TESTING COMMANDS
      if (value.trim().toLowerCase() === "test_temp_dir") {
        this.send_to_terminal = this.$data.dir
          .split("\\")
          .pop()
          .split("/")
          .pop();
      } else if (value.trim().toLowerCase() === "test_par_dir") {
        this.send_to_terminal = this.$data.dir
          .slice(0, this.$data.dir.lastIndexOf("/"))
          .split("\\")
          .pop()
          .split("/")
          .pop();
      } else if (value.trim().toLowerCase() === "test_err_perm") {
        this.send_to_terminal = `<p style="color:red;">[ERROR] You don't have permission to access this directory</p>`;
      } else if (value.trim().toLowerCase() === "main_test") {
        for (let iCount = 0; iCount < this.$data.dirRootArr.length; iCount++) {
          td += "<tr>";
          for (
            let jCount = 0;
            jCount < this.$data.dirRootArr[iCount].length;
            jCount++
          ) {
            if (this.$data.dirRootClass[iCount][jCount] === 1) {
              td +=
                "<td><p style='color:#838383;'>" +
                this.$data.dirRootArr[iCount][jCount] +
                "</p></td>";
            } else if (this.$data.dirRootClass[iCount][jCount] === 2) {
              td +=
                "<td><p style='color:green;'>" +
                this.$data.dirRootArr[iCount][jCount] +
                "</p></td>";
            } else if (this.$data.dirRootClass[iCount][jCount] === 3) {
              td +=
                "<td bgcolor=green><p style='color:#151515;'>" +
                this.$data.dirRootArr[iCount][jCount] +
                "</p></td>";
            }
          }
          td += "</tr>";
        }
        this.send_to_terminal =
          '<table class="table" style="width:70%; margin-top: 5px;">' +
          td +
          "</table>";
      } else if (value.trim().toLowerCase() === "find_test") {
        let serVaal = "tools";
        for (let iCount = 0; iCount < this.$data.dirRootArr.length; iCount++) {
          for (
            let jCount = 0;
            jCount < this.$data.dirRootArr[iCount].length;
            jCount++
          ) {
            if (this.$data.dirRootArr[iCount][jCount] === serVaal) {
              this.send_to_terminal = `${iCount} and ${jCount} : acc => ${
                this.$data.dirRootAcc[iCount][jCount]
              }`;
            }
          }
        }
        //////////////////////////////////////////////////////////////////////////////////////////
        // main commands

        // cd commands
      } else if (
        value
          .trim()
          .toLowerCase()
          .match(/[^\s]+/g)[0] === "cd"
      ) {
        this.$data.newDir = value
          .trim()
          .toLowerCase()
          .match(/[^\s]+/g)[1];

        if (this.$data.newDir !== undefined) {
          this.$data.newDirName =
            this.$data.newDir.slice(0, 1).toUpperCase() +
            this.$data.newDir.slice(1, this.$data.newDir.length);
        } else {
          this.$data.newDir = undefined;
        }

        this.$data.tempDirName = this.$data.dir
          .split("\\")
          .pop()
          .split("/")
          .pop();

        this.$data.parentDirName = this.$data.dir
          .slice(0, this.$data.dir.lastIndexOf("/"))
          .split("\\")
          .pop()
          .split("/")
          .pop();

        if (
          (this.$data.newDir === "data" ||
            this.$data.newDir === "library" ||
            this.$data.newDir === "applications") &&
          this.$data.tempDirName === "henry"
        ) {
          this.$data.dir =
            this.$data.parentDirName +
            "/" + // Parent folder
            this.$data.tempDirName +
            "/" + // Current folder
            this.$data.newDirName; // New directory where we go

          this.$data.banner.sign = `Henry@Ecorp:/~${this.$data.newDirName}#`;
          this.$data.newDir = undefined;
        } else if (
          this.$data.newDir === ".." &&
          this.$data.parentDirName !== undefined
        ) {
          this.send_to_terminal = this.$data.parentDirName;
          if (this.$data.parentDirName === "henry") {
            this.$data.banner.sign = `Henry@Ecorp:~#`;
            this.$data.dir = "/home/henry";
          } else {
            this.$data.banner.sign = `Henry@Ecorp:~${
              this.$data.parentDirName
            }#`;
            this.$data.dir = this.$data.dir.slice(
              0,
              this.$data.dir.lastIndexOf("/")
            );
          }
        } else if (this.$data.newDir === undefined) {
          this.$data.banner.sign = "Henry@Ecorp:~#";
          this.$data.dir = "/home/henry";
        } else {
          this.send_to_terminal = `<p style="color:red;">[ERROR] File or directory "${
            this.$data.newDir
          }" not found</p>`;
        }
      }
      // ls commands
      else if (value.trim().toLowerCase() === "ls") {
        if (this.$data.banner.sign.slice(-5).toLowerCase() === "data#") {
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

        // other commands
      } else if (value.trim().toLowerCase() === "pwd") {
        this.send_to_terminal = this.$data.dir;
      } else {
        this.send_to_terminal = `'${value}' is not recognized as an internal command or external,
an executable program or a script`;
      }
    }
  }
};
</script>

<style>
</style>