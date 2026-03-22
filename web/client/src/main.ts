import {initMap,renderMap} from './map.ts'
import {rooms} from './rooms.ts'
import { renderDevices } from './devices.ts';
import { fetchDevices } from './api.ts';

let devices = await fetchDevices();

function handleWindowResize(){
  const result = initMap('map');
  if(result){
    renderMap(result.ctx, rooms, result.canvas.width / window.devicePixelRatio, result.canvas.height / window.devicePixelRatio);
  }
  return;
}

document.addEventListener('DOMContentLoaded',()=>{
  handleWindowResize();//initial render of map
  window.addEventListener('resize',handleWindowResize);
  renderDevices('devices-panel',devices)
})

