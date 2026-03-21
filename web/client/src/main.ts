import {initMap} from './map.ts'

const result = initMap('map', 10, 10, 20);

if (!result) {
  console.error('failed to init map');
} else {
  console.log('map initialized', result);
}
