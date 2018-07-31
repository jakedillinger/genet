import BaseComponent from './base'
import fs from 'fs'
import genet from '@genet/api'
import glob from 'glob'
import objpath from 'object-path'
import path from 'path'

export default class LibraryComponent extends BaseComponent {
  constructor (comp, dir) {
    super()
    const file = objpath.get(comp, 'main', '')
    if (!file) {
      throw new Error('main field required')
    }

    const searchPaths = ['.']
    for (const spath of searchPaths) {
      const absolute = path.join(dir, spath, file)
      if (fs.existsSync(absolute)) {
        this.mainFile = absolute
        break
      }
    }
    if (!this.mainFile) {
      const libs = glob.sync(
        `crates/${file}/target/${process.env.GENET_TARGET}/*.{dll,so,dylib}`,
        { cwd: dir })
      if (libs.length > 0) {
        this.mainFile = path.join(dir, libs[0])
      }
    }
    if (!this.mainFile) {
      throw new Error(`could not resolve ${file} in ${dir}`)
    }
  }
  async load () {
    this.disposable = genet.session.registerLibrary(
      this.mainFile.replace(/\bapp\.asar\b/, 'app.asar.unpacked'))
    return false
  }
  async unload () {
    if (this.disposable) {
      this.disposable.dispose()
      this.disposable = null
      return false
    }
    return true
  }
}
