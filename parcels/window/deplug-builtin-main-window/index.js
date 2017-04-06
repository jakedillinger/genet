import { ipcRenderer } from 'electron'
import { Argv, Channel, Tab } from 'deplug'
import m from 'mithril'
import jquery from 'jquery'

const tabs = []
const loadedTabs = []
let idCounter = 0

Channel.on('core:create-tab', (_, template) => {
  let tab = Tab.getTemplate(template)
  if (tab.singleton === true) {
    let item = tabs.find((t) => { return t.tab.template === template })
    if (item) {
      return
    }
  }
  tabs.push({
    id: ++idCounter,
    tab: tab
  })
  m.redraw()
})

ipcRenderer.on('tab-deplug-loaded', (_, id) => {
  loadedTabs[id] = true
  m.redraw()
})

class WebView {
  constructor() {

  }

  oncreate(vnode) {
    let webview = vnode.dom
    let item = tabs.find((t) => { return t.id === parseInt(vnode.attrs.id) })
    if (item) {
      webview.addEventListener('dom-ready', () => {
        const argv = JSON.stringify(Argv)
        const tab = JSON.stringify(item)
        const script = `require("deplug-core/tab.main")(${argv}, ${tab})`
        webview.executeJavaScript(script)
      })
    }
  }

  view(vnode) {
    return <webview
      class="tab-content"
      src={`file://${__dirname}/index.htm`}
      isActive={vnode.attrs.isActive}
      isLoaded={vnode.attrs.isLoaded}
      nodeintegration
    >
    </webview>
  }
}

export default class Main {
  constructor() {
    this.currentIndex = 0
  }

  activate(index) {
    this.currentIndex = parseInt(index)
    let content = jquery(`webview[index=${this.currentIndex}]`).get()[0]
  }

  view() {
    return (
      <main>
        <div id="tab-container">
          {
            tabs.map((t, i) => {
              return (
                <a class="tab-label"
                  index={i}
                  isActive={ this.currentIndex === i }
                  onclick={m.withAttr('index', this.activate, this)}
                >
                  { t.tab.name }
                </a>
              )
            })
          }
        </div>
        <div id="tab-mask"></div>
        {
          tabs.map((t, i) => {
            return m(WebView, {
              key: t.id,
              id: t.id,
              index: i,
              isLoaded: (loadedTabs[t.id] === true),
              isActive: this.currentIndex === i
            })
          })
        }
      </main>
    )
  }
}
