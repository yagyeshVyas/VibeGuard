"use client";

import type { ReactNode } from "react";
import { useState, useEffect } from "react";
import Navbar from "@/components/Navbar";
import Footer from "@/components/Footer";
import ParticleField from "@/components/ParticleField";
import HudReadout from "@/components/HudReadout";
import BootSequence from "@/components/BootSequence";
import PageTransition from "@/components/PageTransition";

export default function Shell({ children }: { children: ReactNode }) {
  const [booted, setBooted] = useState(false);

  // Only show boot sequence on first load (home page), skip on others
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

  if (isFirstLoad && !booted) {
    return <BootSequence onDone={handleBootDone} />;
  }

  if (!booted) {
    return null;
  }

  return (
    <>
      <ParticleField />
      <HudReadout />
      <Navbar />
      <main className="relative z-10">
        <PageTransition>{children}</PageTransition>
      </main>
      <Footer />
    </>
  );
}