var url = "https://api.ipify.org?format=json";

$.getJSON(url, function(data) {
  console.log(data.ip);
  display.innerHTML = data.ip;
});