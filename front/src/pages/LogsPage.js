import { html } from 'uhtml'
import { log } from '../log'

let version = "1.0.1"

function shortDate(timestamp) {
    let date = new Date(timestamp)
//    return `${date.getFullYear()}-${date.getMonth()+1}-${date.getDate()+1}`
    return `${date.toISOString()}`
}

window.MHR.register("LogsPage", class LogsPage extends window.MHR.AbstractPage {

    constructor(id) {
        super(id)
    }

    enter() {
        let html = this.html

        let items = []
        for (let i = 0; i < log.num_items(); i++) {
            items.push(log.item(i))
        }

        let theHtml = html`
        <div class="w3-container">
            <h2>${T("Technical logs")} (${version})</h2>
        </div>

        <ul class="w3-ul">
            ${items.map(
            ({timestamp, desc, item}, i) => html`<li>${shortDate(timestamp)}-${desc} ${item}</li>`
            )}
        </ul>

        `;

        this.render(theHtml)
    }
})
