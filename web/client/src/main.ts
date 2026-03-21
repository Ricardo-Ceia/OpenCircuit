import {initMap,drawRoom} from './map.ts'
import {rooms} from './rooms.ts'

document.addEventListener('DOMContentLoaded',()=>{
  const result = initMap('map');

  if (!result) {
    console.error('failed to init map');
    return;
  }

  const { ctx, canvas } = result;

  for (const room of rooms) {
    drawRoom(ctx, room, canvas.width / window.devicePixelRatio, canvas.height / window.devicePixelRatio);
  }
})

