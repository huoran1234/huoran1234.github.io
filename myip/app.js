async function getIP(url){try{return (await (await fetch(url)).text()).trim()}catch(e){return null}}
async function geo(ip){if(!ip)return null;try{return await (await fetch('https://ipinfo.io/'+ip+'/json')).json()}catch(e){return null}}
function card(title,ip,g){let c=document.createElement('div');c.className='card';let country=g&&g.country?g.country:'-';let city=g&&g.city?g.city:'-';let org=g&&g.org?g.org:'-';let tz=g&&g.timezone?g.timezone:'-';c.innerHTML=`<h2>${title}</h2><div class='ip'>${ip||'Not Available'}</div><div class='meta'><div><b>Country</b>: ${country}</div><div><b>City</b>: ${city}</div><div><b>ASN/ISP</b>: ${org}</div><div><b>Timezone</b>: ${tz}</div></div><p><button>Copy</button></p>`;c.querySelector('button').onclick=()=>navigator.clipboard.writeText(ip||'');return c;}
(async()=>{
let v4=await getIP('https://ipv4.icanhazip.com');
let v6=await getIP('https://ipv6.icanhazip.com');
let g4=await geo(v4); let g6=await geo(v6);
let cards=document.getElementById('cards');
cards.append(card('IPv4',v4,g4));
cards.append(card('IPv6',v6,g6));
document.getElementById('ua').textContent='Browser: '+navigator.userAgent;
document.getElementById('tz').textContent='Timezone: '+Intl.DateTimeFormat().resolvedOptions().timeZone;
})();
