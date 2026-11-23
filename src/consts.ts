import type { SvgComponent } from "astro/types"
import Email from "@/assets/icons/email.svg"
import GitHub from "@/assets/icons/github.svg"
import RSS from "@/assets/icons/rss.svg"
import LinkedIn from "@/assets/icons/linkedin.svg"

export const SITE = {
  title: "Arsenic",
  description: "Arsenic's writings (built using @jktrn astro-erudite)",
  locale: "en-US",
  dir: "ltr",
  defaultPageImage: "/static/opengraph-image.png",
  defaultPostImage: "/static/1200x630.png",
} as const

export const NAVIGATION = [
  { href: "/blog", label: "Blog" },
  { href: "/projects", label: "Projects" },
  { href: "/about", label: "About" },
]

export const SOCIALS: { href: string; label: string; icon: SvgComponent }[] = [
  { href: "https://github.com/Aresenix", label: "GitHub", icon: GitHub },
  { href: "https://www.linkedin.com/in/jessica-setiadhi", label: "LinkedIn", icon: LinkedIn },
  { href: "mailto:jess.setiadhi@gmail.com", label: "Email", icon: Email },
  { href: "/rss.xml", label: "RSS", icon: RSS },
]
