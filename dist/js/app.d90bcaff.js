(function(e){function n(n){for(var r,i,l=n[0],s=n[1],d=n[2],u=0,c=[];u<l.length;u++)i=l[u],Object.prototype.hasOwnProperty.call(o,i)&&o[i]&&c.push(o[i][0]),o[i]=0;for(r in s)Object.prototype.hasOwnProperty.call(s,r)&&(e[r]=s[r]);p&&p(n);while(c.length)c.shift()();return a.push.apply(a,d||[]),t()}function t(){for(var e,n=0;n<a.length;n++){for(var t=a[n],r=!0,l=1;l<t.length;l++){var s=t[l];0!==o[s]&&(r=!1)}r&&(a.splice(n--,1),e=i(i.s=t[0]))}return e}var r={},o={app:0},a=[];function i(n){if(r[n])return r[n].exports;var t=r[n]={i:n,l:!1,exports:{}};return e[n].call(t.exports,t,t.exports,i),t.l=!0,t.exports}i.m=e,i.c=r,i.d=function(e,n,t){i.o(e,n)||Object.defineProperty(e,n,{enumerable:!0,get:t})},i.r=function(e){"undefined"!==typeof Symbol&&Symbol.toStringTag&&Object.defineProperty(e,Symbol.toStringTag,{value:"Module"}),Object.defineProperty(e,"__esModule",{value:!0})},i.t=function(e,n){if(1&n&&(e=i(e)),8&n)return e;if(4&n&&"object"===typeof e&&e&&e.__esModule)return e;var t=Object.create(null);if(i.r(t),Object.defineProperty(t,"default",{enumerable:!0,value:e}),2&n&&"string"!=typeof e)for(var r in e)i.d(t,r,function(n){return e[n]}.bind(null,r));return t},i.n=function(e){var n=e&&e.__esModule?function(){return e["default"]}:function(){return e};return i.d(n,"a",n),n},i.o=function(e,n){return Object.prototype.hasOwnProperty.call(e,n)},i.p="/";var l=window["webpackJsonp"]=window["webpackJsonp"]||[],s=l.push.bind(l);l.push=n,l=l.slice();for(var d=0;d<l.length;d++)n(l[d]);var p=s;a.push([0,"chunk-vendors"]),t()})({0:function(e,n,t){e.exports=t("56d7")},"56d7":function(e,n,t){"use strict";t.r(n);var r=t("2b0e"),o=function(){var e=this,n=e.$createElement,t=e._self._c||n;return t("div",{attrs:{id:"app"}},[t("v-shell",{attrs:{banner:e.banner,shell_input:e.send_to_terminal,commands:e.commands},on:{shell_output:e.prompt}})],1)},a=[],i={name:"App",data(){return{send_to_terminal:"",banner:{header:"Sand Shell",helpHeader:'Enter "help" for more information.',emoji:{first:"zero",second:" one",time:750},sign:"Henry@Ecorp:~ $"},commands:[{name:"info",get(){return"<p>INFO</p>"}},{name:"uname",get(){return navigator.appVersion}},{name:"ls",get(){return' \n   <table class="table">\n   <tbody>\n    <tr>\n      <td bgcolor="red"><p color="blue">efhuiu3rh37d.dat</p></td>\n      <td><p style="color:red;">Applications</p></td>\n      <td>Library</td>\n    </tr>\n    <tr>\n      <td>printers.xml</td>\n      <td>app.2ab771f81c1da05a7c9b.xml</td>\n      <td>id_rsa.pub</td>\n    </tr>\n   </tbody>\n   </table>'}}]}},methods:{prompt(e){"ifconfig"===e.trim()?this.send_to_terminal="\n    Wi-Fi wireless network card:\n        \n    Local link IPv6 address. . . : fe80 :: 340f: 6f02: 41e9: 477b% 24\n    IPv4 address. . . . . . . . .: 192.168.1.2\n    Subnet mask. . . . . . . . . : 255.255.255.0\n    Default Gateway. . . . . . . : 192.168.1.1":"cd Data"===e.trim()?this.$data.banner.sign="Henry@Ecorp:Data $":"cd"===e.trim()?this.$data.banner.sign="Henry@Ecorp:~ $":"sudo"===e.trim()?this.send_to_terminal='<p style="color:red;">[ERROR] You are not in the sudoers file. This incident will be reported</p>':this.send_to_terminal=`'${e}' is not recognized as an internal command or external,\nan executable program or a batch file`}}},l=i,s=t("2877"),d=Object(s["a"])(l,o,a,!1,null,null,null),p=d.exports,u=t("77e9");r["a"].config.productionTip=!1,r["a"].use(u["a"]),new r["a"]({render:e=>e(p)}).$mount("#app")}});
//# sourceMappingURL=app.d90bcaff.js.map