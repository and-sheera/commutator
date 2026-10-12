// Composes the app icon: the switchboard artwork, whose wooden body is itself
// the rounded tile, fitted to the macOS icon grid with its shadow.
// Usage: swift scripts/make-icon.swift <out.png> [artwork.png]
import CoreGraphics
import Foundation
import ImageIO
import UniformTypeIdentifiers

let arguments = CommandLine.arguments
let output = URL(fileURLWithPath: arguments.count > 1 ? arguments[1] : "icon.png")
let artworkURL = URL(fileURLWithPath: arguments.count > 2 ? arguments[2] : "Config/IconArtwork.png")
// Side of the square the artwork is drawn into. The body spans 1162 of the
// 1254 px image, so 889 makes it the 824 pt tile of the macOS grid. Tune by eye.
let artworkSide: CGFloat = 889

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

// Centered on the 1024 canvas: the body sits on the 824 pt grid square.
ctx.setShadow(offset: CGSize(width: 0, height: -12), blur: 28, color: rgb(0, 0.3))
ctx.draw(artwork, in: CGRect(x: 512 - artworkSide / 2, y: 512 - artworkSide / 2, width: artworkSide, height: artworkSide))

let destination = CGImageDestinationCreateWithURL(output as CFURL, UTType.png.identifier as CFString, 1, nil)!
CGImageDestinationAddImage(destination, ctx.makeImage()!, nil)
guard CGImageDestinationFinalize(destination) else { fatalError("Не удалось записать \(output.path)") }
