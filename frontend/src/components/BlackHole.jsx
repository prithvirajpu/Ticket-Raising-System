"use client"
import React, { useRef, useMemo } from 'react';
import { Canvas, useFrame } from '@react-three/fiber';
import * as THREE from 'three';

// ─── Constants & Defaults ────────────────────────────────────
const DEFAULT_CENTRE = {
  voidRadius: 1.2,
  voidX: 50, // Ignored in true 3D space as the canvas handles centering
  voidY: 50,
};

const DEFAULTS = {
  showCenter: true,
  centre: DEFAULT_CENTRE,
  particleCount: 1500,
  particleSize: 4,      // Map to proper 3D scale inside
  colors: ["#ff4500", "#da70d6", "#4b0082"], // Premium gradient flow
  outerRadius: 70,      // % scale for total disk extent
  tilt: 25,             // Accretion disk inclination
  tiltSideway: 15,      // Secondary aesthetic rotation angle
  trail: 50,            // Managed via material properties in R3F
  orbitSpeed: 4,
  pullSpeed: 0
};

const COMPONENT_DEFAULTS = {
  showCenter: DEFAULTS.showCenter,
  centre: {
    voidRadius: DEFAULT_CENTRE.voidRadius,
  },
  colors: DEFAULTS.colors,
  outerRadius: DEFAULTS.outerRadius,
  particleCount: DEFAULTS.particleCount,
  particleSize: DEFAULTS.particleSize,
  orbitSpeed: DEFAULTS.orbitSpeed,
  tilt: DEFAULTS.tilt,
  tiltSideway: DEFAULTS.tiltSideway,
};

// ─── Accretion Disk Implementation ───────────────────────────
const AccretionDisk = ({ settings }) => {
  const pointsRef = useRef();

  // Convert raw sliders/props into standard 3D scene dimensions
  const innerR = settings.centre?.voidRadius ?? DEFAULT_CENTRE.voidRadius;
  const outerR = innerR + ((settings.outerRadius ?? DEFAULTS.outerRadius) / 100) * 4.5;
  const particleSize = (settings.particleSize ?? DEFAULTS.particleSize) * 0.015;
  const colorPalette = settings.colors ?? DEFAULTS.colors;

  const [positions, colors] = useMemo(() => {
    const count = settings.particleCount ?? DEFAULTS.particleCount;
    const pos = new Float32Array(count * 3);
    const col = new Float32Array(count * 3);

    // Turn hex string array into accessible THREE.Color structures
    const threeColors = colorPalette.map(c => new THREE.Color(c));

    for (let i = 0; i < count; i++) {
      // Relativistic layout curve: power distribution pulls mass toward the event horizon
      const radius = innerR + Math.pow(Math.random(), 2) * (outerR - innerR);
      const angle = Math.random() * Math.PI * 2;
      
      // Calculate flat disk coordinates
      const x = Math.cos(angle) * radius;
      const z = Math.sin(angle) * radius;
      // Thickness tapers beautifully off near the outer edges
      const y = (Math.random() - 0.5) * 0.6 * (1 - (radius - innerR) / (outerR - innerR));

      pos[i * 3] = x;
      pos[i * 3 + 1] = y;
      pos[i * 3 + 2] = z;

      // Map out smooth color blending across the array length based on particle distance
      const pct = (radius - innerR) / (outerR - innerR);
      const colorIdx = Math.min(Math.floor(pct * (threeColors.length - 1)), threeColors.length - 2);
      const localPct = (pct * (threeColors.length - 1)) - colorIdx;
      
      const mixedColor = threeColors[colorIdx].clone().lerp(threeColors[colorIdx + 1], localPct);
      
      col[i * 3] = mixedColor.r;
      col[i * 3 + 1] = mixedColor.g;
      col[i * 3 + 2] = mixedColor.b;
    }
    return [pos, col];
  }, [settings, innerR, outerR, colorPalette]);

  // Handle the active real-time orbit system 
  useFrame((state) => {
    if (pointsRef.current) {
      const baseSpeed = (settings.orbitSpeed ?? DEFAULTS.orbitSpeed) * 0.1;
      pointsRef.current.rotation.y = state.clock.getElapsedTime() * baseSpeed;
    }
  });

  // Calculate composite Euler angles from custom tilt controls
  const xTilt = ((settings.tilt ?? DEFAULTS.tilt) * Math.PI) / 180;
  const zTilt = ((settings.tiltSideway ?? DEFAULTS.tiltSideway) * Math.PI) / 180;

  return (
    <points ref={pointsRef} rotation={[xTilt, 0, zTilt]}>
      <bufferGeometry>
        <bufferAttribute 
          attach="attributes-position" 
          args={[positions, 3]} 
          count={positions.length / 3} 
          array={positions} 
          itemSize={3} 
        />
        <bufferAttribute 
          attach="attributes-color" 
          args={[colors, 3]} 
          count={colors.length / 3} 
          array={colors} 
          itemSize={3} 
        />
      </bufferGeometry>
      <pointsMaterial 
        size={particleSize} 
        vertexColors 
        transparent 
        opacity={0.85} 
        blending={THREE.AdditiveBlending} 
        depthWrite={false} 
      />
    </points>
  );
};

// ─── Main Black Hole Stage ───────────────────────────────────
export default function BlackHole(props) {
  // Gracefully merge customized parent property hooks with base overrides
  const settings = useMemo(() => {
    return { ...COMPONENT_DEFAULTS, ...props };
  }, [props]);

  const showCenter = settings.showCenter !== false;
  const coreRadius = settings.centre?.voidRadius ?? DEFAULT_CENTRE.voidRadius;

  return (
    <div 
      className="w-full h-[400px] bg-black rounded-2xl overflow-hidden relative border border-neutral-900 shadow-2xl"
      style={props.style}
    >

      <Canvas 
        camera={{ position: [0, 3.5, 6.5], fov: 55 }} 
        gl={{ antialias: true, powerPreference: "high-performance" }}
      >
        <color attach="background" args={['#000000']} />
        <ambientLight intensity={0.4} />
        
        {/* Core Singularity Structure */}
        {showCenter && (
          <mesh>
            <sphereGeometry args={[coreRadius, 32, 32]} />
            <meshBasicMaterial color="#020202" />
          </mesh>
        )}

        {/* Accretion Disk Shell */}
        <AccretionDisk settings={settings} />
      </Canvas>
    </div>
  );
}