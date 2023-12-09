import threading
import sys
import webview
import re
from engineio.async_drivers import gevent
from flask import Flask, render_template, request, flash, redirect, url_for, make_response
from flask_apscheduler import APScheduler
from flask_socketio import SocketIO, emit
from mnemonic import Mnemonic
from utils import *
from secrets import compare_digest
from db import DB
import datetime

privkey = None
address = None
window = None
tx_buffer = None
balance_buffer = 0
con_status = "connecting"

mnemo = Mnemonic("english")

db = DB()

PEER = db.get_peer()

app = Flask(__name__)
app.secret_key = os.urandom(16).hex()

scheduler = APScheduler()
scheduler.init_app(app)
scheduler.start()

socketio = SocketIO(app)


@app.route('/')
def landing():
    return render_template("base.html")


# set token cookie to deny requests from outside of application
@app.route('/auth/<token>')
def auth(token):
    if not compare_digest(token, webview.token):
        return ""
    else:
        r = make_response(redirect(url_for('login')))
        r.set_cookie('auth', token)
        return r


# wallet selection
@app.route("/login", methods=["GET"])
def login():
    token = request.cookies.get('auth')
    if not compare_digest(str(token), webview.token):
        return ""

    wallets = db.get_wallets()
    elements = ""
    for wallet in wallets:
        elements += f"<li><a href='/unlock/{wallet[1]}'>{wallet[1]}</a></li>"

    return render_template("login.html", wallets=elements)


# unlock wallet with password
@app.route("/unlock/<wallet>", methods=["GET", "POST"])
def unlock(wallet):
    global address, privkey, balance_buffer

    token = request.cookies.get('auth')
    if not compare_digest(str(token), webview.token):
        return ""

    if request.method == "POST":
        walletdata = db.get_wallet_by_address(wallet)
        decrypted_pk = decrypt_pk(walletdata[2], request.form.get("pw"), walletdata[3])
        if decrypted_pk is not None:
            addr, pk = wallet_from_pkhex(decrypted_pk)
            address = addr
            privkey = pk
            balance_buffer = walletdata[4]
            scheduler.get_job(id="sync").modify(next_run_time=datetime.datetime.now())
            return redirect(url_for('wallet'))
        else:
            flash('Invalid Password!')
            return redirect(request.url)
    else:
        return render_template("unlock.html")


# add new wallet
@app.route("/add")
def add():
    token = request.cookies.get('auth')
    if not compare_digest(str(token), webview.token):
        return ""

    return render_template("add.html")


# choose password for restored wallet
@app.route("/restore-mnemo", methods=["GET", "POST"])
def restore_mnemo_pw():
    token = request.cookies.get('auth')
    if not compare_digest(str(token), webview.token):
        return ""

    if request.method == "POST":
        password1 = request.form.get("pw1")
        password2 = request.form.get("pw2")

        if password1 != password2:
            flash("Passwords are not the same!")
            return redirect(request.url)
        elif len(password1) < 8:
            flash("Password too short! (min. length: 8)")
            return redirect(request.url)

        return redirect(url_for("restore_mnemo", pw=password1))
    else:
        return render_template("new.html")


# input mnemonic for restored wallet
@app.route("/restore-mnemo/<pw>", methods=["GET", "POST"])
def restore_mnemo(pw):
    global address, privkey

    token = request.cookies.get('auth')
    if not compare_digest(str(token), webview.token):
        return ""

    if request.method == "POST":
        words = request.form.get("mnemo")
        seed = mnemo.to_seed(words, passphrase="")
        address, privkey = wallet_from_seed(seed)

        encrypted_pk, salt = encrypt_pk(privkey.to_string().hex(), pw)

        db.insert_wallet(address, encrypted_pk, salt)
        scheduler.get_job(id="sync").modify(next_run_time=datetime.datetime.now())

        return redirect(url_for("wallet"))
    else:
        return render_template("restore-mnemo.html")


# choose password for restored wallet
@app.route("/restore-pk", methods=["GET", "POST"])
def restore_pk_pw():
    token = request.cookies.get('auth')
    if not compare_digest(str(token), webview.token):
        return ""

    if request.method == "POST":
        password1 = request.form.get("pw1")
        password2 = request.form.get("pw2")

        if password1 != password2:
            flash("Passwords are not the same!")
            return redirect(request.url)
        elif len(password1) < 8:
            flash("Password too short! (min. length: 8)")
            return redirect(request.url)

        return redirect(url_for("restore_pk", pw=password1))
    else:
        return render_template("new.html")


# input pk for restored wallet
@app.route("/restore-pk/<pw>", methods=["GET", "POST"])
def restore_pk(pw):
    global address, privkey

    token = request.cookies.get('auth')
    if not compare_digest(str(token), webview.token):
        return ""

    if request.method == "POST":
        pkhex = request.form.get("pk")
        address, privkey = wallet_from_pkhex(pkhex)

        encrypted_pk, salt = encrypt_pk(privkey.to_string().hex(), pw)

        db.insert_wallet(address, encrypted_pk, salt)
        scheduler.get_job(id="sync").modify(next_run_time=datetime.datetime.now())

        return redirect(url_for("wallet"))
    else:
        return render_template("restore-pk.html")


# generate new wallet
@app.route("/new", methods=["GET", "POST"])
def new():
    global address, privkey

    token = request.cookies.get('auth')
    if not compare_digest(str(token), webview.token):
        return ""

    if request.method == "POST":
        password1 = request.form.get("pw1")
        password2 = request.form.get("pw2")

        if password1 != password2:
            flash("Passwords are not the same!")
            return redirect(request.url)
        elif len(password1) < 8:
            flash("Password too short! (min. length: 8)")
            return redirect(request.url)

        words = mnemo.generate(strength=256)
        seed = mnemo.to_seed(words, passphrase="")
        address, privkey = wallet_from_seed(seed)

        encrypted_pk, salt = encrypt_pk(privkey.to_string().hex(), password1)

        db.insert_wallet(address, encrypted_pk, salt)
        scheduler.get_job(id="sync").modify(next_run_time=datetime.datetime.now())

        return redirect(url_for("new_confirm", mnemonic=words))

    else:

        return render_template("new.html")


# display mnemonic for new wallet
@app.route("/new-confirm/<mnemonic>")
def new_confirm(mnemonic):
    token = request.cookies.get('auth')
    if not compare_digest(str(token), webview.token):
        return ""

    return render_template("new-confirm.html", mnemonic=mnemonic)


# wallet dashboard
@app.route("/wallet")
def wallet():
    token = request.cookies.get('auth')
    if not compare_digest(str(token), webview.token):
        return ""

    return render_template("wallet.html", address=address)


# send transaction
@app.route("/send", methods=["GET", "POST"])
def send():
    global tx_buffer

    token = request.cookies.get('auth')
    if not compare_digest(str(token), webview.token):
        return ""

    if request.method == "POST":
        recipient = request.form.get("recipient")
        amount = request.form.get("amount")
        fee = request.form.get("fee")

        if not re.search("^[a-fA-F0-9]{48}$", recipient):
            flash(f"Invalid recipient.")
            return render_template("send.html")

        try:
            amount = float(amount)
            fee = float(fee)
        except ValueError:
            flash(f"Invalid value.")
            return render_template("send.html")

        amount_int = round(amount * 10 ** 8)
        fee_int = round(fee * 10 ** 8)

        tx_buffer = [recipient, amount_int, fee_int, privkey]

        flash(f"You are sending {amount:.8f} WART to {recipient}.<div class='center'><a class='btn' id='send-confirm' href='/submit'>Confirm</a></div>")
        return render_template("send.html")
    else:
        return render_template("send.html")


# submit transaction to peer
@app.route("/submit")
def submit():
    token = request.cookies.get('auth')
    if not compare_digest(str(token), webview.token):
        return ""

    emit("sending", namespace="/", broadcast=True)

    try:
        r = send_tx(tx_buffer[0], tx_buffer[1], tx_buffer[2], tx_buffer[3], PEER)
        if r['code'] == 0:
            flash('Success!')
            return redirect(url_for("wallet"))
        else:
            flash(str(r))
            return redirect(url_for("send"))
    except requests.exceptions.RequestException as e:
        flash(f"Connection error. Try changing your peer in the settings.")
        return redirect(url_for("send"))


# settings
@app.route("/settings", methods=["GET", "POST"])
def settings():
    global PEER

    token = request.cookies.get('auth')
    if not compare_digest(str(token), webview.token):
        return ""

    if request.method == "POST":
        PEER = request.form.get("peer")
        db.update_peer(PEER)
        flash("Settings saved!")
        return render_template("settings.html", peer=PEER)
    else:
        return render_template("settings.html", peer=PEER)


# delete confirm
@app.route("/delete")
def delete_confirm():
    token = request.cookies.get('auth')
    if not compare_digest(str(token), webview.token):
        return ""

    return render_template("delete.html", address=address)


# delete wallet
@app.route("/delete/<address>")
def delete_wallet(address):
    token = request.cookies.get('auth')
    if not compare_digest(str(token), webview.token):
        return ""

    db.delete_wallet(address)
    return redirect(url_for("login"))


# exit application
@app.route("/exit")
def exit_app():
    token = request.cookies.get('auth')
    if not compare_digest(str(token), webview.token):
        return ""
    if address is not None:
        db.update_balance(address, balance_buffer)
    window.destroy()
    sys.exit()


# sync
@scheduler.task('interval', id='sync', seconds=10, misfire_grace_time=20)
def sync():
    global con_status

    with scheduler.app.app_context():
        global balance_buffer
        if address is not None:
            b = get_balance(PEER, address)
            if b is not None:
                balance_buffer = b
                con_status = "connected"
            else:
                con_status = "disconnected"
            print("Synced")


# socketio
@socketio.on('connect')
def first_connect():
    balances = f"""<p class="wallet-amount">{balance_buffer} WART</p><p class="wallet-amountusd">0 USD</p>"""
    emit("overview", {"data": balances}, namespace="/")
    emit("con", {"data": con_status}, namespace="/")


@socketio.on('update_wallet')
def update_wallet():
    balances = f"""<p class="wallet-amount">{balance_buffer} WART</p><p class="wallet-amountusd">0 USD</p>"""
    emit("overview", {"data": balances}, namespace="/")
    emit("con", {"data": con_status}, namespace="/")


def start_server():
    socketio.run(app, host='localhost', port=50050)


if __name__ == '__main__':
    t = threading.Thread(target=start_server)
    t.daemon = True
    t.start()

    window = webview.create_window("WART Wallet", "http://localhost:50050/", width=1280, height=720, text_select=True,
                                   resizable=False, background_color="#212121", frameless=True, easy_drag=False)
    webview.start(set_token, window)
    sys.exit()
