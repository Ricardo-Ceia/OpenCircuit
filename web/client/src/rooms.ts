import type {Room} from './types.ts'

export const rooms: Room[] = [
  {
    name: "Living Room",
    color: "#e8f4e8",
    points: [
      { x: 0.0, y: 0.0 },
      { x: 0.45, y: 0.0 },
      { x: 0.45, y: 0.55 },
      { x: 0.0, y: 0.55 },
    ],
  },
  {
    name: "Kitchen",
    color: "#fef9e7",
    points: [
      { x: 0.45, y: 0.0 },
      { x: 1.0, y: 0.0 },
      { x: 1.0, y: 0.45 },
      { x: 0.45, y: 0.45 },
    ],
  },
  {
    name: "Bedroom",
    color: "#eaf0fb",
    points: [
      { x: 0.0, y: 0.55 },
      { x: 0.4, y: 0.55 },
      { x: 0.4, y: 1.0 },
      { x: 0.0, y: 1.0 },
    ],
  },
  {
    name: "Bathroom",
    color: "#fce8f3",
    points: [
      { x: 0.4, y: 0.7 },
      { x: 0.65, y: 0.7 },
      { x: 0.65, y: 1.0 },
      { x: 0.4, y: 1.0 },
    ],
  },
  {
    name: "Hallway",
    color: "#f5f0e8",
    points: [
      { x: 0.4, y: 0.45 },
      { x: 1.0, y: 0.45 },
      { x: 1.0, y: 0.7 },
      { x: 0.4, y: 0.7 },
    ],
  },
  {
    name: "Second Bedroom",
    color: "#edf5f0",
    points: [
      { x: 0.65, y: 0.7 },
      { x: 1.0, y: 0.7 },
      { x: 1.0, y: 1.0 },
      { x: 0.65, y: 1.0 },
    ],
  },
];
