from pathlib import Path
import os

from flask import Flask , redirect , url_for , request , render_template, session
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from sqlalchemy import text
import pickle
import pandas as pd
import plotly.express as px
import plotly.figure_factory as ff

BASE_DIR = Path(__file__).resolve().parent
GRAPH_DATA_PATH = BASE_DIR / 'data' / 'cicids2017_sample.csv'

app = Flask(__name__)
CORS(app)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'development-only-secret')

database_url = os.environ.get('DATABASE_URL')
if database_url:
    if database_url.startswith('postgres://'):
        database_url = database_url.replace('postgres://', 'postgresql+psycopg://', 1)
    elif database_url.startswith('postgresql://'):
        database_url = database_url.replace('postgresql://', 'postgresql+psycopg://', 1)
else:
    database_url = f"sqlite:///{BASE_DIR / 'instance' / 'users.db'}"

app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {'pool_pre_ping': True}
db = SQLAlchemy(app)
app.static_folder = str(BASE_DIR / 'static')
app.config['STATIC_FOLDER'] = str(BASE_DIR / 'static')



class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))

    def __init__(self, username, password):
        self.username = username
        self.password = password

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/health')
def health():
    try:
        db.session.execute(text('SELECT 1'))
        return {'status': 'ok', 'database': 'connected'}
    except Exception:
        db.session.rollback()
        return {'status': 'degraded', 'database': 'unavailable'}, 503



@app.route('/register/', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            db.session.add(User(username=request.form['username'], password=request.form['password']))
            db.session.commit()
            return redirect(url_for('login'))
        except:
            return render_template('register.html', message="User Already Exists")
    else:
        return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    else:
        u = request.form['username']
        p = request.form['password']
        data = User.query.filter_by(username=u, password=p).first()
        if data is not None:
            session['logged_in'] = True
            return redirect('prediction')
        
        return render_template('login.html', message="Incorrect Details")


@app.route('/logout', methods=['GET', 'POST'])
def logout():
    session['logged_in'] = False
    return redirect(url_for('index'))


@app.route('/prediction', methods=['GET', 'POST'])
def prediction():
    return render_template('prediction.html')


with open(BASE_DIR / 'model1.pkl', 'rb') as model_file:
    model = pickle.load(model_file)


def get_attack_type(encoded_value):
  attack_types = {  
    0: 'BEGIN',
    1: 'Bot',
    2: 'DDoS',
    3: 'DoS GoldenEye',
    4: 'DoS Hulk',
    5: 'DoS Slowhttptest',
    6: 'DoS slowloris',
    7: 'FTP-Patator',
    8: 'Heartbleed',
    9: 'Infiltration',
    10: 'PortScan',
    11: 'SSH-Patator',
    12: 'Web Attack - Brute Force',
    13: 'Web Attack - Sql Injection',
    14: 'Web Attack - XSS'
  }
  
  return attack_types.get(encoded_value, "Unknown")


@app.route('/result',methods=['POST'])
def result():
    Destination_Port = int(request.form["Destination_Port"])
    Flow_Duration = int(request.form["Flow_Duration"])
    Total_Fwd_Packets = int(request.form["Total_Fwd_Packets"])
    Total_Backward_Packets = int(request.form["Total_Backward_Packets"])
    Total_Length_of_Fwd_Packets = int(request.form["Total_Length_of_Fwd_Packets"])
    Total_Length_of_Bwd_Packets = int(request.form["Total_Length_of_Bwd_Packets"])
    Fwd_Packet_Length_Max = int(request.form["Fwd_Packet_Length_Max"])
    Fwd_Packet_Length_Min = int(request.form["Fwd_Packet_Length_Min"])
    Fwd_Packet_Length_Mean = int(request.form["Fwd_Packet_Length_Mean"])
    Fwd_Packet_Length_Std = int(request.form["Fwd_Packet_Length_Std"])
    Bwd_Packet_Length_Max = int(request.form["Bwd_Packet_Length_Max"])
    Bwd_Packet_Length_Min = int(request.form["Bwd_Packet_Length_Min"])
    Bwd_Packet_Length_Mean = int(request.form["Bwd_Packet_Length_Mean"])
    Bwd_Packet_Length_Std = int(request.form["Bwd_Packet_Length_Std"])
    Flow_Bytes_s = int(request.form["Flow_Bytes/s"])
    Flow_Packets_s = int(request.form["Flow_Packets/s"])
    Flow_IAT_Mean = int(request.form["Flow_IAT_Mean"])
    Flow_IAT_Std = int(request.form["Flow_IAT_Std"])
    Flow_IAT_Max = int(request.form["Flow_IAT_Max"])
    Flow_IAT_Min = int(request.form["Flow_IAT_Min"])
    Fwd_IAT_Total = int(request.form["Fwd_IAT_Total"])
    Fwd_IAT_Mean = int(request.form["Fwd_IAT_Mean"])
    Fwd_IAT_Std = int(request.form["Fwd_IAT_Std"])
    Fwd_IAT_Max = int(request.form["Fwd_IAT_Max"])
    Fwd_IAT_Min = int(request.form["Fwd_IAT_Min"])
    Bwd_IAT_Total = int(request.form["Bwd_IAT_Total"])
    Bwd_IAT_Mean = int(request.form["Bwd_IAT_Mean"])
    Bwd_IAT_Std = int(request.form["Bwd_IAT_Std"])
    Bwd_IAT_Max = int(request.form["Bwd_IAT_Max"])
    Bwd_IAT_Min = int(request.form["Bwd_IAT_Min"])
    Fwd_PSH_Flags = int(request.form["Fwd_PSH_Flags"])
    Fwd_URG_Flags = int(request.form["Fwd_URG_Flags"])
    Fwd_Header_Length = int(request.form["Fwd_Header_Length"])
    Bwd_Header_Length = int(request.form["Bwd_Header_Length"])
    Fwd_Packets_s = int(request.form["Fwd_Packets/s"])
    Bwd_Packets_s = int(request.form["Bwd_Packets/s"])
    Min_Packet_Length = int(request.form["Min_Packet_Length"])
    Max_Packet_Length = int(request.form["Max_Packet_Length"])
    Packet_Length_Mean = int(request.form["Packet_Length_Mean"])
    Packet_Length_Std = int(request.form["Packet_Length_Std"])
    Packet_Length_Variance = int(request.form["Packet_Length_Variance"])
    FIN_Flag_Count = int(request.form["FIN_Flag_Count"])
    SYN_Flag_Count = int(request.form["SYN_Flag_Count"])
    RST_Flag_Count = int(request.form["RST_Flag_Count"])
    PSH_Flag_Count = int(request.form["PSH_Flag_Count"])
    ACK_Flag_Count = int(request.form["ACK_Flag_Count"])
    URG_Flag_Count = int(request.form["URG_Flag_Count"])
    CWE_Flag_Count = int(request.form["CWE_Flag_Count"])
    ECE_Flag_Count = int(request.form["ECE_Flag_Count"])
    Down_Up_Ratio = int(request.form["Down/Up_Ratio"])
    Average_Packet_Size = int(request.form["Average_Packet_Size"])
    Avg_Fwd_Segment_Size = int(request.form["Avg_Fwd_Segment_Size"])
    Avg_Bwd_Segment_Size = int(request.form["Avg_Bwd_Segment_Size"])
    Fwd_Header_Length_1 = int(request.form["Fwd_Header_Length.1"])
    Fwd_Avg_Bytes_Bulk = int(request.form["Fwd_Avg_Bytes/Bulk"])
    Fwd_Avg_Packets_Bulk = int(request.form["Fwd_Avg_Packets/Bulk"])
    Fwd_Avg_Bulk_Rate = int(request.form["Fwd_Avg_Bulk_Rate"])
    Bwd_Avg_Bytes_Bulk = int(request.form["Bwd_Avg_Bytes/Bulk"])
    Bwd_Avg_Packets_Bulk = int(request.form["Bwd_Avg_Packets/Bulk"])
    Bwd_Avg_Bulk_Rate = int(request.form["Bwd_Avg_Bulk_Rate"])
    Subflow_Fwd_Packets = int(request.form["Subflow_Fwd_Packets"])
    Subflow_Fwd_Bytes = int(request.form["Subflow_Fwd_Bytes"])
    Subflow_Bwd_Packets = int(request.form["Subflow_Bwd_Packets"])
    Subflow_Bwd_Bytes = int(request.form["Subflow_Bwd_Bytes"])
    Init_Win_bytes_forward = int(request.form["Init_Win_bytes_forward"])
    Init_Win_bytes_backward = int(request.form["Init_Win_bytes_backward"])
    act_data_pkt_fwd = int(request.form["act_data_pkt_fwd"])
    min_seg_size_forward = int(request.form["min_seg_size_forward"])
    Active_Mean = int(request.form["Active_Mean"])
    Active_Std = int(request.form["Active_Std"])
    Active_Max = int(request.form["Active_Max"])
    Active_Min = int(request.form["Active_Min"])
    Idle_Mean = int(request.form["Idle_Mean"])
    Idle_Std = int(request.form["Idle_Std"])
    Idle_Max = int(request.form["Idle_Max"])
    Idle_Min = int(request.form["Idle_Min"])


    input_data = {
    'Destination_Port': Destination_Port, 
    'Flow_Duration': Flow_Duration,
    'Total_Fwd_Packets': Total_Fwd_Packets,
    'Total_Backward_Packets': Total_Backward_Packets,
    'Total_Length_of_Fwd_Packets': Total_Length_of_Fwd_Packets,
    'Total_Length_of_Bwd_Packets': Total_Length_of_Bwd_Packets,
    'Fwd_Packet_Length_Max': Fwd_Packet_Length_Max,
    'Fwd_Packet_Length_Min': Fwd_Packet_Length_Min,
    'Fwd_Packet_Length_Mean': Fwd_Packet_Length_Mean,
    'Fwd_Packet_Length_Std': Fwd_Packet_Length_Std,
    'Bwd_Packet_Length_Max': Bwd_Packet_Length_Max,
    'Bwd_Packet_Length_Min': Bwd_Packet_Length_Min,
    'Bwd_Packet_Length_Mean': Bwd_Packet_Length_Mean,
    'Bwd_Packet_Length_Std': Bwd_Packet_Length_Std,
    'Flow_Bytes_s': Flow_Bytes_s,
    'Flow_Packets_s': Flow_Packets_s,
    'Flow_IAT_Mean': Flow_IAT_Mean,
    'Flow_IAT_Std': Flow_IAT_Std,
    'Flow_IAT_Max': Flow_IAT_Max,
    'Flow_IAT_Min': Flow_IAT_Min,
    'Fwd_IAT_Total': Fwd_IAT_Total,
    'Fwd_IAT_Mean': Fwd_IAT_Mean,
    'Fwd_IAT_Std': Fwd_IAT_Std,
    'Fwd_IAT_Max': Fwd_IAT_Max,
    'Fwd_IAT_Min': Fwd_IAT_Min,
    'Bwd_IAT_Total': Bwd_IAT_Total,
    'Bwd_IAT_Mean': Bwd_IAT_Mean,
    'Bwd_IAT_Std': Bwd_IAT_Std,
    'Bwd_IAT_Max': Bwd_IAT_Max,
    'Bwd_IAT_Min': Bwd_IAT_Min,
    'Fwd_PSH_Flags': Fwd_PSH_Flags,
    'Fwd_URG_Flags': Fwd_URG_Flags,
    'Fwd_Header_Length': Fwd_Header_Length,
    'Bwd_Header_Length': Bwd_Header_Length,
    'Fwd_Packets_s': Fwd_Packets_s,
    'Bwd_Packets_s': Bwd_Packets_s,
    'Min_Packet_Length': Min_Packet_Length,
    'Max_Packet_Length': Max_Packet_Length,
    'Packet_Length_Mean': Packet_Length_Mean,
    'Packet_Length_Std': Packet_Length_Std,
    'Packet_Length_Variance': Packet_Length_Variance,
    'FIN_Flag_Count': FIN_Flag_Count,
    'SYN_Flag_Count': SYN_Flag_Count,
    'RST_Flag_Count': RST_Flag_Count,
    'PSH_Flag_Count': PSH_Flag_Count,
    'ACK_Flag_Count': ACK_Flag_Count,
    'URG_Flag_Count': URG_Flag_Count,
    'CWE_Flag_Count': CWE_Flag_Count,
    'ECE_Flag_Count': ECE_Flag_Count,
    'Down_Up_Ratio': Down_Up_Ratio,
    'Average_Packet_Size': Average_Packet_Size,
    'Avg_Fwd_Segment_Size': Avg_Fwd_Segment_Size,
    'Avg_Bwd_Segment_Size': Avg_Bwd_Segment_Size,
    'Fwd_Header_Length_1': Fwd_Header_Length_1,
    'Fwd_Avg_Bytes_Bulk': Fwd_Avg_Bytes_Bulk,
    'Fwd_Avg_Packets_Bulk': Fwd_Avg_Packets_Bulk,
    'Fwd_Avg_Bulk_Rate': Fwd_Avg_Bulk_Rate,
    'Bwd_Avg_Bytes_Bulk': Bwd_Avg_Bytes_Bulk,
    'Bwd_Avg_Packets_Bulk': Bwd_Avg_Packets_Bulk,
    'Bwd_Avg_Bulk_Rate': Bwd_Avg_Bulk_Rate,
    'Subflow_Fwd_Packets': Subflow_Fwd_Packets,
    'Subflow_Fwd_Bytes': Subflow_Fwd_Bytes,
    'Subflow_Bwd_Packets': Subflow_Bwd_Packets,
    'Subflow_Bwd_Bytes': Subflow_Bwd_Bytes,
    'Init_Win_bytes_forward': Init_Win_bytes_forward,
    'Init_Win_bytes_backward': Init_Win_bytes_backward,
    'act_data_pkt_fwd': act_data_pkt_fwd,
    'min_seg_size_forward': min_seg_size_forward,
    'Active_Mean': Active_Mean,
    'Active_Std': Active_Std,
    'Active_Max': Active_Max,
    'Active_Min': Active_Min,
    'Idle_Mean': Idle_Mean,
    'Idle_Std': Idle_Std,
    'Idle_Max': Idle_Max,
    'Idle_Min': Idle_Min
}


    print(input_data)
    input_data_numerical = {key: int(value) for key, value in input_data.items()}
    input_df = pd.DataFrame([input_data_numerical])
    prediction = model.predict(input_df)
    result = get_attack_type(prediction[0])
    return render_template('result.html',result=result)



@app.route('/graph1')
def graph1():
    intro = pd.read_csv(GRAPH_DATA_PATH)
    
    label_counts = intro['Attack Type'].value_counts().reset_index()
    label_counts.columns = ['Attack Type', 'Count']
    
    fig = px.bar(
        label_counts,
        x='Attack Type',
        y='Count',
        title="Bar plot of Attack Types",
        labels={'Attack Type': 'Attack Type', 'Count': 'Count'}
    )
    
    plot_json = fig.to_json()
    return render_template('graph1.html', plot_json=plot_json)


@app.route('/graph2')
def graph2():
    intro = pd.read_csv(GRAPH_DATA_PATH)
    
    fig = px.histogram(
        intro,
        x='Min Packet Length',
        nbins=30,
        title="Distribution of Minimum Packet Length",
        labels={'Min Packet Length': 'Minimum Packet Length'}
    )
    
    plot_json = fig.to_json()
    return render_template('graph2.html', plot_json=plot_json)


@app.route('/graph3')
def graph3():
    intro = pd.read_csv(GRAPH_DATA_PATH)
    
    fig = px.box(
        intro,
        x='Attack Type',
        y='Flow Duration',
        title="Flow Duration by Attack Type",
        labels={'Flow Duration': 'Flow Duration'}
    )
    
    plot_json = fig.to_json()
    return render_template('graph3.html', plot_json=plot_json)



@app.route('/graph4')
def graph4():
    intro = pd.read_csv(GRAPH_DATA_PATH)
    
    attack_counts = intro['Attack Type'].value_counts().reset_index()
    attack_counts.columns = ['Attack Type', 'Count']
    
    fig = px.pie(
        attack_counts,
        names='Attack Type',
        values='Count',
        title="Attack Type Distribution"
    )
    
    plot_json = fig.to_json()
    return render_template('graph4.html', plot_json=plot_json)



if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(host="0.0.0.0", port=int(__import__('os').environ.get('PORT', 5000)))


with app.app_context():
    db.create_all()