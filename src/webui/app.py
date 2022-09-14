#!/usr/bin/env python3
import os
import glob
from flask import (Flask, render_template, 
				request, redirect)


INTERACTIONS_D = "../interactions"
INTERACTION_SEPERATOR = "---- SNIP ----"

app = Flask(__name__)

# BASIC APP to browse the collected data a bit.

def query_domains(query: str) -> []:  
	domain_path = os.path.join(INTERACTIONS_D, os.path.basename(query))
	result = []
	print(domain_path)
	for f in glob.glob(domain_path):
		if os.path.isdir(f):
			result.append((os.path.basename(f), os.listdir(f)))
	return result


@app.route('/', methods=["GET"])
def home():
	return redirect("/show")


@app.route("/show", methods=["GET"])
def show():
	return render_template("home.html", domains=os.listdir(INTERACTIONS_D))


@app.route("/show/<query>", methods=["GET"])
def show_search(query: str):
	return render_template("home.html", 
		interactions=query_domains(query)), 200


@app.route("/get/interaction", methods=["GET"])
def get_interaction():
	target = os.path.basename(request.args.get("target", ""))
	interaction = os.path.basename(request.args.get("interaction", ""))
	file_path = os.path.join(INTERACTIONS_D, target, interaction)
	if not os.path.exists(file_path) or os.path.isdir(file_path):
		return "", 404
	interaction_content = open(
		file_path, 'r', errors="ignore").read().split(INTERACTION_SEPERATOR)
	return render_template("interaction.html", interaction=interaction_content), 200


@app.route("/clean", methods=["POST"])
def clean():
	if os.path.exists(INTERACTIONS_D):
		app.log.info("[*] Cleaning INTERACTIONS_D")
		shutil.rmtree(INTERACTIONS_D)
	return redirect("/")


app.run("127.0.0.1", 1337, debug=True)
