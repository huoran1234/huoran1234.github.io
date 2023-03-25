//  import ol from './ol';
const init = () => {
  const copySvg = document.querySelector(".copySvg");
  const mapDiv = document.querySelector("#map");
  let location =  { lat: 0,lng: 0}
  copySvg.addEventListener(
    "click",
    () => {
      const ipIU = document.querySelector(".ip");
      ipIU.select();
      ipIU.setSelectionRange(0, 99999);

      try {
        document.execCommand("copy")
          ? alert("Ip is now on clipBoard for your convinience.")
          : alert("Something went Wrong... Try again");
      } catch (error) {
        console.error("Unable to copy", error);
      }
    },
    false
  );

  fetch("https://ipinfo.io/json")
    .then((response) => response.json())
    .then((data) => {
      let { ip, org, city, region, country, loc, postal } = data;
      loc = loc.split(',')
      const lat = parseFloat(loc[0])
      const lng = parseFloat(loc[1])
      const ipUI = document.querySelector(".ip");
      ipUI.value = ip;
      const locationUI = document.querySelector(".location");
      locationUI.innerHTML = `${city}, ${region}, ${country}`;
      
      var map = new ol.Map({
        target: 'map',
        layers: [
          new ol.layer.Tile({
            source: new ol.source.OSM()
          })
        ],
        view: new ol.View({
          center: ol.proj.fromLonLat([lng, lat]),
          zoom: 12
        })
      });    
    })
    .catch((err) => console.error(err));
};

init();

