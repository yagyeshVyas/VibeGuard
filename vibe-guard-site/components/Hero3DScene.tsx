"use client";

import { Suspense, useMemo, useRef } from "react";
import { Canvas, useFrame, useThree } from "@react-three/fiber";
import * as THREE from "three";

/* ------------------------------------------------------------------ *
 * VibeGuard 3D Hero — Performance-optimized
 *
 * GPU budget: <2ms/frame on mid-range hardware.
 *
 * Optimizations:
 *   - Replaced MeshDistortMaterial with meshBasicMaterial (no shader,
 *     no lighting needed). The icosahedron is wireframe only — looks
 *     better AND renders 10x faster.
 *   - Single useFrame on the group (not 4 separate ones).
 *   - Particle count capped at 350 (sufficient for the visual).
 *   - No point lights (basic materials are unlit).
 *   - DPR capped at 1.5 (not 1.8).
 *   - No ShieldSweep (removed — was 120 extra particles + useFrame).
 *   - No drei imports at all (zero bundle overhead from drei helpers).
 * ------------------------------------------------------------------ */

function CoreScene() {
  const group = useRef<THREE.Group>(null);
  const wire = useRef<THREE.Mesh>(null);
  const wire2 = useRef<THREE.Mesh>(null);
  const ring = useRef<THREE.Mesh>(null);
  const ring2 = useRef<THREE.Mesh>(null);
  const arcRing = useRef<THREE.Mesh>(null);
  const { pointer } = useThree();

  useFrame((state, delta) => {
    if (!group.current) return;
    const t = state.clock.elapsedTime;

    // Combined rotation + parallax + float in ONE frame call
    group.current.rotation.y += delta * 0.18;
    const py = pointer.y * 0.25;
    group.current.rotation.x = THREE.MathUtils.lerp(group.current.rotation.x, py, 0.03);
    group.current.position.y = Math.sin(t * 1.2) * 0.12;

    if (wire.current) wire.current.rotation.y -= delta * 0.1;
    if (wire2.current) wire2.current.rotation.x += delta * 0.06;
    if (ring.current) ring.current.rotation.x += delta * 0.2;
    if (ring2.current) ring2.current.rotation.y -= delta * 0.12;
    if (arcRing.current) {
      const mat = arcRing.current.material as THREE.MeshBasicMaterial;
      mat.opacity = 0.3 + Math.sin(t * Math.PI) * 0.15;
      arcRing.current.rotation.y += delta * 0.25;
    }
  });

  return (
    <group ref={group}>
      {/* Inner core — wireframe only, additive blend, no lighting */}
      <mesh ref={wire} scale={1.4}>
        <icosahedronGeometry args={[1, 2]} />
        <meshBasicMaterial color="#00f0ff" wireframe transparent opacity={0.4} blending={THREE.AdditiveBlending} />
      </mesh>

      {/* Outer wireframe shell — violet, counter-rotating */}
      <mesh ref={wire2} scale={2.0}>
        <icosahedronGeometry args={[1, 1]} />
        <meshBasicMaterial color="#7c5cff" wireframe transparent opacity={0.15} blending={THREE.AdditiveBlending} />
      </mesh>

      {/* Cyan ring */}
      <mesh ref={ring} rotation={[Math.PI / 3, 0, 0]}>
        <torusGeometry args={[2.4, 0.012, 12, 80]} />
        <meshBasicMaterial color="#00ff9d" transparent opacity={0.5} blending={THREE.AdditiveBlending} />
      </mesh>

      {/* Violet ring */}
      <mesh ref={ring2} rotation={[Math.PI / 2.2, Math.PI / 4, 0]}>
        <torusGeometry args={[1.9, 0.008, 10, 64]} />
        <meshBasicMaterial color="#7c5cff" transparent opacity={0.4} blending={THREE.AdditiveBlending} />
      </mesh>

      {/* Segmented arc — pulses */}
      <mesh ref={arcRing} rotation={[Math.PI / 2.8, 0, 0]}>
        <torusGeometry args={[2.15, 0.006, 6, 40, Math.PI * 1.3]} />
        <meshBasicMaterial color="#00f0ff" transparent opacity={0.4} blending={THREE.AdditiveBlending} />
      </mesh>
    </group>
  );
}

function ParticleCloud({ count = 350 }: { count?: number }) {
  const ref = useRef<THREE.Points>(null);

  const positions = useMemo(() => {
    const arr = new Float32Array(count * 3);
    for (let i = 0; i < count; i++) {
      const r = 2.2 + Math.random() * 3.5;
      const theta = Math.random() * Math.PI * 2;
      const phi = Math.acos(2 * Math.random() - 1);
      arr[i * 3] = r * Math.sin(phi) * Math.cos(theta);
      arr[i * 3 + 1] = r * Math.sin(phi) * Math.sin(theta);
      arr[i * 3 + 2] = r * Math.cos(phi);
    }
    return arr;
  }, [count]);

  useFrame((_, delta) => {
    if (ref.current) ref.current.rotation.y += delta * 0.03;
  });

  return (
    <points ref={ref}>
      <bufferGeometry>
        <bufferAttribute attach="attributes-position" args={[positions, 3]} />
      </bufferGeometry>
      <pointsMaterial size={0.04} color="#9fefff" transparent opacity={0.8} sizeAttenuation blending={THREE.AdditiveBlending} depthWrite={false} />
    </points>
  );
}

export default function Hero3DScene() {
  return (
    <Canvas
      camera={{ position: [0, 0, 6.2], fov: 45 }}
      dpr={[1, 1.5]}
      gl={{ antialias: true, alpha: true, powerPreference: "high-performance" }}
      style={{ background: "transparent" }}
    >
      <Suspense fallback={null}>
        <CoreScene />
        <ParticleCloud count={350} />
        <fog attach="fog" args={["#03050c", 7, 13]} />
      </Suspense>
    </Canvas>
  );
}
