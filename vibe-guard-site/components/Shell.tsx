"use client";

import type { ReactNode } from "react";
import { useState, useEffect } from "react";
import Navbar from "@/components/Navbar";
import Footer from "@/components/Footer";
import HudReadout from "@/components/HudReadout";
import BootSequence from "@/components/BootSequence";
import PageTransition from "@/components/PageTransition";
import ScrollEffects from "@/components/ScrollEffects";

export default function Shell({ children }: { children: ReactNode }) {
  const [booted, setBooted] = useState(false);

  const [isFirstLoad, setIsFirstLoad] = useState(true);
  useEffect(() => {
    const seen = sessionStorage.getItem("vg-booted");
    if (seen) {
      setIsFirstLoad(false);
      setBooted(true);
    }
  }, []);

  const handleBootDone = () => {
    sessionStorage.setItem("vg-booted", "true");
    setBooted(true);
  };

  return (
    <>
      {/* Main content always mounted — loads behind boot overlay so
       * the 3D scene initializes while the boot animation plays.
       * The boot overlay sits on top (z-100) and does a curtain
       * wipe to reveal the content underneath. */}
      <HudReadout />
      <ScrollEffects />
      <Navbar />
      <main className="relative z-10">
        <PageTransition>{children}</PageTransition>
      </main>
      <Footer />

      {/* Boot overlay — renders on top until dismissed */}
      {isFirstLoad && !booted && <BootSequence onDone={handleBootDone} />}
    </>
  );
}
