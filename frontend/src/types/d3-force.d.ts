declare module 'd3-force' {
  export interface SimulationNodeDatum {
    index?: number;
    x?: number;
    y?: number;
    vx?: number;
    vy?: number;
    fx?: number | null;
    fy?: number | null;
  }

  export interface SimulationLinkDatum<T = SimulationNodeDatum> {
    source: T | string | number;
    target: T | string | number;
  }

  export interface Force<N extends SimulationNodeDatum, L extends SimulationLinkDatum<N>> {
    (nodes: N[]): Force<N, L>;
    initialize: (nodes: N[]) => void;
  }

  export interface Simulation<N extends SimulationNodeDatum, L extends SimulationLinkDatum<N>> {
    nodes: N[];
    links: L[];
    alpha: number;
    alphaMin: number;
    alphaDecay: number;
    alphaTarget: number;
    velocityDecay: number;
    nodes(): N[];
    on(typename: string, callback: () => void): Simulation<N, L>;
    force(name: string): Force<N, L> | undefined;
    force(name: string, force: Force<N, L>): Simulation<N, L>;
    restart(): Simulation<N, L>;
    stop(): Simulation<N, L>;
    tick(): Simulation<N, L>;
    alphaTarget(value: number): Simulation<N, L>;
  }

  export function forceSimulation<N extends SimulationNodeDatum = SimulationNodeDatum, L extends SimulationLinkDatum<N> = SimulationLinkDatum<N>>(nodes?: N[]): Simulation<N, L>;

  export function forceManyBody<N extends SimulationNodeDatum = SimulationNodeDatum>(): Force<N, SimulationLinkDatum<N>>;

  export function forceLink<N extends SimulationNodeDatum = SimulationNodeDatum, L extends SimulationLinkDatum<N> = SimulationLinkDatum<N>>(links?: L[]): Force<N, L>;

  export function forceCollide<N extends SimulationNodeDatum = SimulationNodeDatum>(radius?: ((d: N, i: number, nodes: N[]) => number) | number): Force<N, SimulationLinkDatum<N>>;

  export function forceX<N extends SimulationNodeDatum = SimulationNodeDatum>(x?: number): Force<N, SimulationLinkDatum<N>>;

  export function forceY<N extends SimulationNodeDatum = SimulationNodeDatum>(y?: number): Force<N, SimulationLinkDatum<N>>;
}
