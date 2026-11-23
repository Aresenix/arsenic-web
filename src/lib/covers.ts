// Custom covers for songs that have no album art on Last.fm.
//
// 1. Put the image in public/covers/ (square works best, e.g. 600x600).
// 2. Add a line below: "Artist - Song": "/covers/your-file.png",
//    Artist and song must match what Last.fm shows (capitalisation doesn't matter).
//
// Songs not listed here show DEFAULT_COVER.
const DEFAULT_COVER = "/covers/no-cover.png"

const COVERS: Record<string, string> = {
  // "idreamu - WANT iT GIRL+++": "/covers/want-it-girl.png",
}

const normalize = (s: string) => s.trim().toLowerCase()

const lookup = new Map(
  Object.entries(COVERS).map(([key, path]) => [normalize(key), path]),
)

export function coverFor(artist: string, song: string): string {
  return lookup.get(normalize(`${artist} - ${song}`)) ?? DEFAULT_COVER
}
