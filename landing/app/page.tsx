import Nav from "@/components/Nav";
import Hero from "@/components/Hero";
import Marquee from "@/components/Marquee";
import Audits from "@/components/Audits";
import AgentsCarousel from "@/components/AgentsCarousel";
import Architecture from "@/components/Architecture";
import Terminal from "@/components/Terminal";
import FindingsTable from "@/components/FindingsTable";
import Stats from "@/components/Stats";
import Manifesto from "@/components/Manifesto";
import Footer from "@/components/Footer";

export default function Home() {
  return (
    <>
      <Nav />
      <Hero />
      <Marquee />
      <Audits />
      <AgentsCarousel />
      <Architecture />
      <Terminal />
      <FindingsTable />
      <Stats />
      <Manifesto />
      <Footer />
    </>
  );
}
