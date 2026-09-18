// Composes the app icon: the switchboard artwork on a light macOS tile.
// Usage: swift scripts/make-icon.swift <out.png> [artwork.png]
import CoreGraphics
import Foundation
import ImageIO
import UniformTypeIdentifiers

let arguments = CommandLine.arguments
let output = URL(fileURLWithPath: arguments.count > 1 ? arguments[1] : "icon.png")
let artworkURL = URL(fileURLWithPath: arguments.count > 2 ? arguments[2] : "Config/IconArtwork.png")
// Side of the square the artwork is drawn into; its opaque part is narrower
// than the image itself. Tune by eye.
let artworkSide: CGFloat = 780

let space = CGColorSpace(name: CGColorSpace.sRGB)!
func rgb(_ hex: UInt32, _ alpha: CGFloat = 1) -> CGColor {
    func c(_ shift: UInt32) -> CGFloat { CGFloat((hex >> shift) & 0xFF) / 255 }
    return CGColor(srgbRed: c(16), green: c(8), blue: c(0), alpha: alpha)
}

guard let source = CGImageSourceCreateWithURL(artworkURL as CFURL, nil),
      let artwork = CGImageSourceCreateImageAtIndex(source, 0, nil) else {
    fatalError("Не удалось прочитать \(artworkURL.path)")
}
let ctx = CGContext(data: nil, width: 1024, height: 1024, bitsPerComponent: 8, bytesPerRow: 0,
                    space: space, bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!
ctx.interpolationQuality = .high

// macOS icon grid: an 824 pt rounded square inside the 1024 canvas.
let tile = CGPath(roundedRect: CGRect(x: 100, y: 100, width: 824, height: 824), cornerWidth: 185, cornerHeight: 185, transform: nil)
ctx.saveGState()
ctx.setShadow(offset: CGSize(width: 0, height: -12), blur: 28, color: rgb(0, 0.3))
ctx.addPath(tile); ctx.setFillColor(rgb(0xF3EEE7)); ctx.fillPath()
ctx.restoreGState()

ctx.addPath(tile); ctx.clip()
let background = CGGradient(colorsSpace: space, colors: [rgb(0xFFFFFF), rgb(0xEAE2D6)] as CFArray, locations: nil)!
ctx.drawLinearGradient(background, start: CGPoint(x: 512, y: 924), end: CGPoint(x: 512, y: 100), options: [])
ctx.setShadow(offset: CGSize(width: 0, height: -14), blur: 26, color: rgb(0x3A2410, 0.3))
ctx.draw(artwork, in: CGRect(x: 512 - artworkSide / 2, y: 512 - artworkSide / 2, width: artworkSide, height: artworkSide))

let destination = CGImageDestinationCreateWithURL(output as CFURL, UTType.png.identifier as CFString, 1, nil)!
CGImageDestinationAddImage(destination, ctx.makeImage()!, nil)
guard CGImageDestinationFinalize(destination) else { fatalError("Не удалось записать \(output.path)") }
