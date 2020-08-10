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
        header: "Sand Shell",
        helpHeader: 'Enter "help" for more information.',
        emoji: {
          first: "zero",
          second: " one",
          time: 750
        },
        sign: `Henry@Ecorp:~ $`
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
        },
        {
          name: "ls",
          get() {
            return ` 
   <table class="table">
   <tbody>
    <tr>
      <td bgcolor="red"><p color="blue">efhuiu3rh37d.dat</p></td>
      <td><p style="color:red;">Applications</p></td>
      <td>Library</td>
    </tr>
    <tr>
      <td>printers.xml</td>
      <td>app.2ab771f81c1da05a7c9b.xml</td>
      <td>id_rsa.pub</td>
    </tr>
   </tbody>
   </table>`;
          }
        }
      ]
    };
  },
  methods: {
    prompt(value) {
      if (value.trim().slice(0, 4) === "sudo") {
        this.send_to_terminal = `<p style="color:red;">[ERROR] You are not in the sudoers file. This incident will be reported</p>`;
      } else {
        if (value.trim() === "ifconfig") {
          this.send_to_terminal = `
    Wi-Fi wireless network card:
        
    Local link IPv6 address. . . : fe80 :: 340f: 6f02: 41e9: 477b% 24
    IPv4 address. . . . . . . . .: 192.168.1.2
    Subnet mask. . . . . . . . . : 255.255.255.0
    Default Gateway. . . . . . . : 192.168.1.1`;
        } else if (value.trim() === "cd Data") {
          this.$data.banner.sign = "Henry@Ecorp:Data $";
        } else if (value.trim() === "cd") {
          this.$data.banner.sign = "Henry@Ecorp:~ $";
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