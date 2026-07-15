"use client";

import { useGSAP } from "@gsap/react";
import gsap from "gsap";
import { ScrollTrigger } from "gsap/ScrollTrigger";

gsap.registerPlugin(useGSAP, ScrollTrigger);

/* ================================================================
 * GSAP SCROLL EFFECTS — PERFORMANCE-TUNED
 *
 * Reduced to 3 essential scrub types to minimize ScrollTrigger
 * recalculations on scroll (each trigger = a scroll listener).
 * Framer-motion handles entrance reveals separately.
 *
 *   [data-parallax="40"]  -> vertical parallax (background layers)
 *   [data-rule-line]      -> underline draw (scaleX 0→1)
 *   [data-float-in]       -> simple opacity+y entrance
 * ================================================================ */

export default function ScrollEffects() {
  useGSAP(() => {
    const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (reduce) return;

    // Vertical parallax — background glows only
    gsap.utils.toArray<HTMLElement>("[data-parallax]").forEach((el) => {
      const strength = Number(el.dataset.parallax) || 30;
      gsap.fromTo(
        el,
        { y: -strength },
        {
          y: strength,
          ease: "none",
          scrollTrigger: {
            trigger: el,
            start: "top bottom",
            end: "bottom top",
            scrub: 2,
          },
        }
      );
    });

    // Rule line draw
    gsap.utils.toArray<HTMLElement>("[data-rule-line]").forEach((line) => {
      gsap.fromTo(
        line,
        { scaleX: 0 },
        {
          scaleX: 1,
          transformOrigin: "left center",
          ease: "power2.out",
          scrollTrigger: {
            trigger: line,
            start: "top 88%",
            toggleActions: "play none none none",
          },
        }
      );
    });

    // Simple float-in entrance (no bounce, no scrub)
    gsap.utils.toArray<HTMLElement>("[data-float-in]").forEach((el) => {
      gsap.fromTo(
        el,
        { y: 40, opacity: 0 },
        {
          y: 0,
          opacity: 1,
          duration: 0.6,
          ease: "power2.out",
          scrollTrigger: {
            trigger: el,
            start: "top 88%",
            toggleActions: "play none none none",
          },
        }
      );
    });

    let resizeTimer: ReturnType<typeof setTimeout>;
    const onResize = () => {
      clearTimeout(resizeTimer);
      resizeTimer = setTimeout(() => ScrollTrigger.refresh(), 300);
    };
    window.addEventListener("resize", onResize);
  });

  return null;
}
