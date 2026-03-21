import {initMap,drawRoom,renderMap} from './map.ts'
import {rooms} from './rooms.ts'

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
})

