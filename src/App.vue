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
        dir_parent: " ",
        dir: "~"
      },
      commands: [
        {
          name: "info",
          get() {
            return `<p>INFO</p>`;
          }
        },
        {
          name: "uname",
          get() {
            return navigator.appVersion;
          }
        }
      ]
    };
  },
  methods: {
    prompt(value) {
      if (
        value
          .trim()
          .slice(0, 4)
          .toLowerCase() === "sudo"
      ) {
        this.send_to_terminal = `<p style="color:red;">[ERROR] You are not in the sudoers file. This incident will be reported</p>`;
      } else {
        if (value.trim().toLowerCase() === "ifconfig") {
          this.send_to_terminal = `
    Wi-Fi wireless network card:
        
    Local link IPv6 address. . . : fe80 :: 340f: 6f02: 41e9: 477b% 24
    IPv4 address. . . . . . . . .: 192.168.1.2
    Subnet mask. . . . . . . . . : 255.255.255.0
    Default Gateway. . . . . . . : 192.168.1.1`;
        } else if (value.trim().toLowerCase() === "cd data") {
          this.$data.banner.sign = "Henry@Ecorp:/Data#";
        } else if (value.trim().toLowerCase() === "cd") {
          this.$data.banner.sign = "Henry@Ecorp:~#";
        } else if (value.trim().toLowerCase() === "ls") {
          if (this.$data.banner.sign.slice(-5).toLowerCase() === "data#") {
            this.send_to_terminal = "Data_Files.dat";
          } else {
            this.send_to_terminal = `<table class="table" style="width:70%; margin-top: 0px;">
              <tr>
                <td><p style="color:red;">efhuiu3rh37d.dat</p></td>
                <td><p style="color:green;">Applications</p></td>
                <td><p style="color:green;">Library</p></td>
              </tr>
              <tr>
                <td>printers.xml</td>
                <td><p style="color:red;">Data</p></td>
                <td><p>d_rsa.pub</p></td>
              </tr>
            </table>`;
          }
          this.$data.banner.sign = "Henry@Ecorp:~#";
        } else {
          this.send_to_terminal = `'${value}' is not recognized as an internal command or external,
an executable program or a batch file`;
        }
      }
    }
  }
};
</script>

<style>
</style>