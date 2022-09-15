#!/usr/bin/env python3
import os
import glob
import sqlite3
import click
from flask import (Flask, render_template, 
				request, redirect, g, abort)

INTERACTIONS_DB = "../interactions.db"

app = Flask(__name__)

# BASIC APP to browse the collected data a bit.
# Add basic formatting to make requests fun to look at.
# Try parsing the body if the data format is recognized, for example XML or JSON.

### EXPECTED DB SCHEMA :: Normally created by the MITM
## CREATE TABLE interaction (
##   rowid INTERGER AUTOINCREMENT,
##   cid TEXT,
##   host TEXT,
##   port INTEGER,
##   request BLOB,
##   response BLOB,
##   timestamp TEXT
## )
##

def query_domains(query: str) -> []:  
	db = get_db()
	c = db.cursor()
	res = c.execute(
		"SELECT rowid, host, port FROM interaction WHERE host LIKE :query",
		 {"query": "%" + query + "%"}).fetchall()
	c.close()
	return res


def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(app.config["db"])
    return g.db


@app.route('/', methods=["GET"])
def home():
	return redirect("/show")


@app.route("/show", methods=["GET"])
def show():
	db = get_db()
	c = db.cursor()
	res = c.execute("SELECT DISTINCT host FROM interaction").fetchall()
	c.close()
	return render_template("home.html", domains=res)


@app.route("/show/<query>", methods=["GET"])
def show_search(query: str):
	return render_template("home.html", 
		interactions=query_domains(query), q=query), 200


@app.route("/get/interaction", methods=["GET"])
def get_interaction():
	rid = request.args.get("target", None)
	if rid is None: abort(404)
	db = get_db()
	c = db.cursor()
	interaction = db.execute(
		"SELECT request, response from interaction WHERE rowid=:rid", 
		{"rid": rid}).fetchone()
	c.close()
	return render_template("interaction.html", interaction=interaction), 200


@app.route("/clean", methods=["POST"])
def clean():
	if os.path.exists(app.config["db"]):
		app.logger.info(f"[*] Cleaning {app.config['db']}.")
		os.unlink(app.config["db"])
	return redirect("/")


@app.teardown_appcontext
def teardown_db(app):
    db = g.pop('db', None)
    if db is not None:
        db.close()


@click.command()
@click.option('--interface', '-i', default="127.0.0.1", 
	          help="Specify the interface to serve on.")
@click.option('--port', '-p', default=1337, 
		      help="Specify the port to listen on.")
@click.option('--db', default=INTERACTIONS_DB, 
			  help="Specify the db to use as source.")
def main(interface, port, db):
	app.config["db"] = db
	app.run(interface, port)

if __name__ == "__main__":
	main()
