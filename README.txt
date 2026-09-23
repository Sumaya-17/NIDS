Project Topic - Network intrusion detection using flask and machine learning.

Deployment notes
----------------
The local execution steps below are unchanged. Local runs use the existing
SQLite database at Flask_App/instance/users.db when DATABASE_URL is not set.

Render deployment uses PostgreSQL automatically through render.yaml. The full
CICIDS2017 CSV is stored with Git LFS because it is larger than GitHub's normal
file limit. Flask_App/data/cicids2017_sample.csv is the smaller graph sample
used by the deployed dashboard; the full dataset remains available for the
notebook and training workflows.

To migrate the existing local users to the Render PostgreSQL database, set
DATABASE_URL to the internal Render database connection string and run from
Flask_App:

        python migrate_sqlite_to_postgres.py

The migration is additive and does not overwrite users already in PostgreSQL.

Open anaconda Promt ---
Type - cd Path_of_SourceCode
Enter
Type - python app.py 
python version = Python 3.12.7


1.Data Collection
	The Data Collection module is the foundation of the intrusion detection system. 
        It involves gathering network traffic data from reliable sources such as CICIDS2017,
        NSL-KDD, or custom packet captures. 

2.Data Pre Processing 
	The Data Pre-processing module prepares raw network data for machine learning algorithms. 
        It involves cleaning, formatting, normalizing, and 
        converting categorical features into numerical values using encoding techniques. 

3.Machine Learning Engine
	The Data Pre-processing module prepares raw network data for machine learning algorithms.
        It involves cleaning, formatting, normalizing, and converting categorical 
        features into numerical values using encoding techniques.


4.Flask Web Application Interface
	This module provides a user-friendly interface using Flask, a lightweight Python web framework. 
        It enables users to interact with the intrusion detection system through a browser. 

5.Alert and Reporting Module
        The Alert and Reporting module is responsible for notifying users or administrators
        when suspicious or malicious activity is detected. Once the ML engine classifies traffic as an attack, 
        this module triggers alerts—either on the web interface or via email/SMS if configured. 

6.Database
        The Database module is designed to store and manage all data related to the intrusion detection system. 
        This includes historical input records, prediction outcomes, alert logs, and user interactions. .


		