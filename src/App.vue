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
        "bin",
        "dev",
        "lib",
        "libx32",
        "mnt",
        "root",
        "snap",
        "tmp",
        "boot",
        "etc",
        "lib32",
        "lost+found",
        "opt",
        "run",
        "srv",
        "usr",
        "cdrom",
        "home",
        "lib64",
        "tools",
        "proc",
        "sbin",
        "sys",
        "var"
      ],
      dirRootClass: [
        2,
        1,
        2,
        2,
        1,
        1,
        1,
        3,
        1,
        1,
        2,
        1,
        1,
        1,
        1,
        1,
        1,
        1,
        2,
        1,
        1,
        2,
        1,
        1
      ],
      dirRootAcc: [
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        1,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        1,
        0,
        1,
        0,
        0,
        0,
        0
      ],
      dirHomeArr: [
        "efhuiu3rh37d.dat",
        "Applications",
        "Library",
        "printers.xml",
        "Data",
        "Desktop",
        "Documents",
        "id_rsa.pub"
      ],
      dirHomeClass: [0, 1, 1, 0, 1, 1, 1, 0],
      dirHomeAcc: [1, 1, 1, 1, 1, 1, 1, 1],
      dirToolsArr: [
        "MANIFEST.in",
        "data",
        "data.json",
        "serializekiller.py",
        "weblogic.py"
      ],
      dirToolsClass: [0, 1, 0, 0, 0],
      dirToolsAcc: [1, 1, 1, 1, 1],

      dirHomeDirArr: ["henry"],
      dirHomeDirClass: [0],
      dirHomeDirAcc: [1],

      dirToolsDataArr: [
        "0fgizn7z02.dat",
        "3tkcl5awgy.dat",
        "4jpg7moa9g.dat",
        "5kkqf92qm5.dat",
        "7op6ypyn7k.dat",
        "h18i60bahg.dat",
        "m91ft6waa8.dat",
        "rigw2zlzcz.dat",
        "s2vvij1g3k.dat",
        "xf49c7k6j1.dat"
      ],
      dirToolsDataClass: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
      dirToolsDataAcc: [1, 1, 1, 1, 1, 1, 1, 1, 1, 1],

      dirTmpArr: [
        "Untitled Document 1~sav1.txt",
        "Untitled Document 1~sav2.txt",
        "Untitled Document 1~sav3.txt",
        "Untitled Document 1~sav4.txt",
        "Untitled Document 1~sav5.txt",
        "Untitled Document 1~sav6.txt"
      ],
      dirTmpClass: [0, 0, 0, 0, 0, 0],
      dirTmpAcc: [1, 1, 1, 1, 1, 1],

      dirDesktopArr: [
        "HR Form Drafts",
        "nems-integration.png",
        "faa-swim-sfdps-architecture.jpg",
        "faa-fri-nocc-artcc.png",
        "FIXM_US_Extension_v3_0_Logical_Model_Diagrams.pdf"
      ],
      dirDesktopClass: [1, 0, 0, 0, 0],
      dirDesktopAcc: [1, 1, 1, 1, 1],

      dirHRFormDraftsArr: [
        "draft_1.png",
        "draft_2.png",
        "draft_3.png",
        "draft_4.png"
      ],
      dirHRFormDraftsClass: [0, 0, 0, 0],
      dirHRFormDraftsAcc: [1, 1, 1, 1],

      dirDocumentsArr: [
        "Employee Forms.pdf",
        "ground_floor.jpg",
        "storage_map.jpg",
        "pwd_memo.png",
        "pwd_memo2.png",
        "screening_flyer.jpg",
        "gamenight_flyer.jpg"
      ],
      dirDocumentsClass: [0, 0, 0, 0, 0, 0, 0],
      dirDocumentsAcc: [1, 1, 1, 1, 1, 1, 1],

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
          loop  txqueuelen 1000  (Loacl Loopback(Loopback))
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

        // Files to html
      } else if (value.trim().toLowerCase() === "main_test") {
        for (let iCount = 0; iCount < this.$data.dirRootArr.length; iCount++) {
          if (this.$data.dirRootClass[iCount] === 1) {
            td +=
              "<p style='color:#838383;'>" +
              this.$data.dirRootArr[iCount] +
              "</p>";
          } else if (this.$data.dirRootClass[iCount] === 2) {
            td +=
              "<p style='color:green;'>" +
              this.$data.dirRootArr[iCount] +
              "</p>";
          } else if (this.$data.dirRootClass[iCount] === 3) {
            td +=
              "<p style='color:#151515;background-color:green;width:30px;'>" +
              this.$data.dirRootArr[iCount] +
              "</p>";
          }
        }
        this.send_to_terminal = td;

        // Find by name
      } else if (value.trim().toLowerCase() === "find_test") {
        let serVaal = "tools";
        let result = -1;
        for (let iCount = 0; iCount < this.$data.dirRootArr.length; iCount++) {
          if (this.$data.dirRootArr[iCount] === serVaal) {
            result = 0;
            this.send_to_terminal = `${iCount} : acc => ${
              this.$data.dirRootAcc[iCount]
            } result: ${result}`;
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

        if (this.$data.dir !== "/") {
          this.$data.tempDirName = this.$data.dir
            .split("\\")
            .pop()
            .split("/")
            .pop();
        } else this.$data.tempDirName = "/";

        if (this.$data.dir !== "/") {
          this.$data.parentDirName = this.$data.dir
            .slice(0, this.$data.dir.lastIndexOf("/"))
            .split("\\")
            .pop()
            .split("/")
            .pop();
        } else this.$data.parentDirName = "/";

        if (this.$data.newDir !== "..") {
          let searchValue = this.$data.newDir;
          let exist = false;
          let accessAllowed = false;
          let searchArr = [];
          let accessArr = [];

          if (this.$data.tempDirName.toLowerCase() === "henry") {
            searchArr = this.$data.dirHomeArr;
            accessArr = this.$data.dirHomeAcc;
          }
          if (this.$data.tempDirName === "/") {
            searchArr = this.$data.dirRootArr;
            accessArr = this.$data.dirRootAcc;
          }
          if (this.$data.tempDirName.toLowerCase() === "data") {
            searchArr = this.$data.dirDataArr;
            accessArr = this.$data.dirDataAcc;
          }
          if (this.$data.tempDirName.toLowerCase() === "tools") {
            searchArr = this.$data.dirToolsArr;
            accessArr = this.$data.dirToolsAcc;
          }
          if (this.$data.tempDirName.toLowerCase() === "home") {
            searchArr = this.$data.dirHomeDirArr;
            accessArr = this.$data.dirHomeDirAcc;
          }

          for (let iCount = 0; iCount < searchArr.length; iCount++) {
            if (searchArr[iCount].toLowerCase() === searchValue) {
              exist = true;
              if (accessArr[iCount] === 1) {
                accessAllowed = true;
              }
            }
          }

          if (exist) {
            if (accessAllowed) {
              if (this.$data.tempDirName === "/") {
                this.$data.dir =
                  this.$data.parentDirName + this.$data.newDirName;
              } else {
                this.$data.dir =
                  this.$data.parentDirName +
                  "/" + // Parent folder
                  this.$data.tempDirName +
                  "/" + // Current folder
                  this.$data.newDirName; // New directory where we go
              }

              if (this.$data.newDirName.toLowerCase() === "henry") {
                this.$data.banner.sign = `Henry@Ecorp:~#`;
              } else
                this.$data.banner.sign = `Henry@Ecorp:/~${
                  this.$data.newDirName
                }#`;
            } else {
              this.send_to_terminal = `<p style="color:red;">[ERROR] You don't have permission to access this directory</p>`;
            }
          } else {
            this.send_to_terminal = `<p style="color:red;">[ERROR] File or directory "${
              this.$data.newDir
            }" not found</p>`;
          }

          this.$data.newDir = undefined;
        } else if (
          this.$data.newDir === ".." &&
          this.$data.parentDirName !== undefined
        ) {
          this.send_to_terminal = this.$data.parentDirName;
          if (this.$data.parentDirName.toLowerCase() === "henry") {
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
            if (this.$data.dir === "") {
              this.$data.dir = "/";
            }
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
      else if (
        value
          .trim()
          .toLowerCase()
          .match(/[^\s]+/g)[0] === "ls"
      ) {
        let files = [[]];
        let classification = [[]];
        let currDir = "";

        if (this.$data.dir !== "/") {
          currDir = this.$data.dir
            .split("\\")
            .pop()
            .split("/")
            .pop();
        } else currDir = this.$data.dir;

        if (currDir.toLowerCase() === "data") {
          files = this.$data.dirRootArr;
          classification = this.$data.dirRootClass;
        } else if (currDir.toLowerCase() === "henry") {
          files = this.$data.dirHomeArr;
          classification = this.$data.dirHomeClass;
        } else if (currDir.toLowerCase() === "home") {
          files = this.$data.dirHomeDirArr;
          classification = this.$data.dirHomeDirClass;
        } else if (currDir.toLowerCase() === "/") {
          files = this.$data.dirRootArr;
          classification = this.$data.dirRootClass;
        }

        for (let iCount = 0; iCount < files.length; iCount++) {
          if (classification[iCount] === 0) {
            td += "<p>" + files[iCount] + "</p>";
          } else if (classification[iCount] === 1) {
            td += "<p style='color:#838383;'>" + files[iCount] + "</p>";
          } else if (classification[iCount] === 2) {
            td += "<p style='color:green;'>" + files[iCount] + "</p>";
          } else if (classification[iCount] === 3) {
            td +=
              "<p style='color:#151515;background-color:green;width:30px;'>" +
              files[iCount] +
              "</p>";
          }
        }
        this.send_to_terminal = td;
      }

      // other commands
      else if (value.trim().toLowerCase() === "pwd") {
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