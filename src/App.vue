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

      // ROOT DIR
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

      // HOME/HENRY DIR
      dirHomeArr: [
        "efhuiu3rh37d.dat",
        "Applications",
        "printers.xml",
        "Data",
        "Desktop",
        "Documents",
        "Images",
        "Videos",
        "anaconda3",
        "NVIDIA_CUDA-10.0_Samples",
        "HandShake.cap",
        "WPADump2_01.log.csv",
        "id_rsa.pub"
      ],
      dirHomeClass: [0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0],
      dirHomeAcc: [1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 1],

      // ROOT/TOOLS DIR
      dirToolsArr: [
        "MANIFEST.in",
        "data",
        "data.json",
        "serializekiller.py",
        "weblogic.py"
      ],
      dirToolsClass: [0, 1, 0, 0, 0],
      dirToolsAcc: [1, 1, 1, 1, 1],

      // ROOT/HOME DIR
      dirHomeDirArr: ["henry"],
      dirHomeDirClass: [0],
      dirHomeDirAcc: [1],

      // ROOT/TOOLS/DATA DIR
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

      // ROOT/TMP DIR
      dirTmpArr: [
        "Untitled_Document_1~sav1.txt",
        "Untitled_Document_1~sav2.txt",
        "Untitled_Document_1~sav3.txt",
        "Untitled_Document_1~sav4.txt",
        "Untitled_Document_1~sav5.txt",
        "Untitled_Document_1~sav6.txt"
      ],
      dirTmpClass: [0, 0, 0, 0, 0, 0],
      dirTmpAcc: [1, 1, 1, 1, 1, 1],

      // /HOME/HENRY/DESKTOP DIR
      dirDesktopArr: [
        "HR_Form_Drafts",
        "nems-integration.png",
        "faa-swim-sfdps-architecture.jpg",
        "faa-fri-nocc-artcc.png",
        "FIXM_US_Extension_v3_0_Logical_Model_Diagrams.pdf"
      ],
      dirDesktopClass: [1, 0, 0, 0, 0],
      dirDesktopAcc: [1, 1, 1, 1, 1],

      // /HOME/HENRY/HRFORMSDRAFTS DIR
      dirHRFormDraftsArr: [
        "draft_1.png",
        "draft_2.png",
        "draft_3.png",
        "draft_4.png"
      ],
      dirHRFormDraftsClass: [0, 0, 0, 0],
      dirHRFormDraftsAcc: [1, 1, 1, 1],

      // HOME/HENRY/DOCUMENTS
      dirDocumentsArr: [
        "Employee_Forms.pdf",
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
          let directory = false;
          let accessAllowed = false;
          let searchArr = [];
          let accessArr = [];
          let classArr = [];

          if (this.$data.tempDirName.toLowerCase() === "henry") {
            searchArr = this.$data.dirHomeArr;
            accessArr = this.$data.dirHomeAcc;
            classArr = this.$data.dirHomeClass;
          } else if (this.$data.tempDirName === "/") {
            searchArr = this.$data.dirRootArr;
            accessArr = this.$data.dirRootAcc;
            classArr = this.$data.dirRootClass;
          } else if (
            this.$data.tempDirName.toLowerCase() === "data" &&
            this.$data.parentDirName.toLowerCase() === "henry"
          ) {
            searchArr = this.$data.dirDataArr;
            accessArr = this.$data.dirDataAcc;
            classArr = this.$data.dirDataClass;
          } else if (
            this.$data.tempDirName.toLowerCase() === "documents" &&
            this.$data.parentDirName.toLowerCase() === "henry"
          ) {
            searchArr = this.$data.dirDocumentsArr;
            accessArr = this.$data.dirDocumentsAcc;
            classArr = this.$data.dirDocumentsClass;
          } else if (
            this.$data.tempDirName.toLowerCase() === "desktop" &&
            this.$data.parentDirName.toLowerCase() === "henry"
          ) {
            searchArr = this.$data.dirDesktopArr;
            accessArr = this.$data.dirDesktopAcc;
            classArr = this.$data.dirDesktopClass;
          } else if (
            this.$data.tempDirName.toLowerCase() === "hr_form_drafts" &&
            this.$data.parentDirName.toLowerCase() === "desktop"
          ) {
            searchArr = this.$data.dirHRFormDraftsArr;
            accessArr = this.$data.dirHRFormDraftsAcc;
            classArr = this.$data.dirHRFormDraftsClass;
          } else if (
            this.$data.tempDirName.toLowerCase() === "data" &&
            this.$data.parentDirName.toLowerCase() === "tools"
          ) {
            searchArr = this.$data.dirToolsDataArr;
            accessArr = this.$data.dirToolsDataAcc;
            classArr = this.$data.dirToolsDataClass;
          } else if (this.$data.tempDirName.toLowerCase() === "tools") {
            searchArr = this.$data.dirToolsArr;
            accessArr = this.$data.dirToolsAcc;
            classArr = this.$data.dirToolsClass;
          } else if (this.$data.tempDirName.toLowerCase() === "home") {
            searchArr = this.$data.dirHomeDirArr;
            accessArr = this.$data.dirHomeDirAcc;
            classArr = this.$data.dirHomeDirClass;
          } else if (this.$data.tempDirName.toLowerCase() === "tmp") {
            searchArr = this.$data.dirTmpArr;
            accessArr = this.$data.dirTmpAcc;
            classArr = this.$data.dirTmpClass;
          }

          for (let iCount = 0; iCount < searchArr.length; iCount++) {
            if (searchArr[iCount].toLowerCase() === searchValue) {
              exist = true;
              if (accessArr[iCount] === 1) {
                accessAllowed = true;
              }
              if (classArr[iCount] !== 0) {
                directory = true;
              }
            }
          }

          if (exist) {
            if (directory) {
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
              } else
                this.send_to_terminal = `<p style="color:red;">[ERROR] You don't have permission to access this directory</p>`;
            } else
              this.send_to_terminal = `<p style="color:red;">[ERROR] You can't cd to file</p>`;
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
        let parentDir = "";

        if (this.$data.dir !== "/") {
          currDir = this.$data.dir
            .split("\\")
            .pop()
            .split("/")
            .pop();
        } else currDir = this.$data.dir;

        parentDir = this.$data.dir
          .slice(0, this.$data.dir.lastIndexOf("/"))
          .split("\\")
          .pop()
          .split("/")
          .pop();

        if (currDir.toLowerCase() === "henry") {
          files = this.$data.dirHomeArr;
          classification = this.$data.dirHomeClass;
        } else if (currDir === "/") {
          files = this.$data.dirRootArr;
          classification = this.$data.dirRootClass;
        } else if (
          currDir.toLowerCase() === "data" &&
          parentDir.toLowerCase() === "henry"
        ) {
          files = this.$data.dirDataArr;
          classification = this.$data.dirDataClass;
        } else if (
          currDir.toLowerCase() === "documents" &&
          parentDir.toLowerCase() === "henry"
        ) {
          files = this.$data.dirDocumentsArr;
          classification = this.$data.dirDocumentsClass;
        } else if (
          currDir.toLowerCase() === "desktop" &&
          parentDir.toLowerCase() === "henry"
        ) {
          files = this.$data.dirDesktopArr;
          classification = this.$data.dirDesktopClass;
        } else if (
          currDir.toLowerCase() === "hr_form_drafts" &&
          parentDir.toLowerCase() === "desktop"
        ) {
          files = this.$data.dirHRFormDraftsArr;
          classification = this.$data.dirHRFormDraftsClass;
        } else if (
          currDir.toLowerCase() === "data" &&
          parentDir.toLowerCase() === "tools"
        ) {
          files = this.$data.dirToolsDataArr;
          classification = this.$data.dirToolsDataClass;
        } else if (currDir.toLowerCase() === "tools") {
          files = this.$data.dirToolsArr;
          classification = this.$data.dirToolsClass;
        } else if (currDir.toLowerCase() === "home") {
          files = this.$data.dirHomeDirArr;
          classification = this.$data.dirHomeDirClass;
        } else if (currDir.toLowerCase() === "tmp") {
          files = this.$data.dirTmpArr;
          classification = this.$data.dirTmpClass;
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