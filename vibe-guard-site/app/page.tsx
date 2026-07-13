"use client";

import Shell from "@/components/Shell";
import Hero from "@/components/Hero";
import TerminalDemo from "@/components/TerminalDemo";
import Stats from "@/components/Stats";
import Features from "@/components/Features";
import WhatItCatches from "@/components/WhatItCatches";
import Playground from "@/components/Playground";
import Benchmark from "@/components/Benchmark";
import ClientsCommands from "@/components/ClientsCommands";

export default function Page() {
  return (
    <Shell>
      <Hero />
      <TerminalDemo />
      <Stats />
      <Features />
      <WhatItCatches />
      <Playground />
      <Benchmark />
      <ClientsCommands />
    </Shell>
  );
}