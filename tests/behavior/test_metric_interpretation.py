from datetime import datetime, timezone
import pytest
from intentx.behavior.anomaly import BehavioralAnomalyTrainer
from intentx.behavior.dataset import BehavioralBaselineDataset
from intentx.behavior.explainer import BehavioralAnomalyExplainer, FeatureAttribution, WindowExplanation
from intentx.behavior.mitigation import MitigationRecommender
from intentx.telemetry.windowing import BehavioralWindow


@pytest.fixture
def reference_explainer():
    names=BehavioralWindow.FEATURE_NAMES_V2
    dataset=BehavioralBaselineDataset(feature_names=tuple(names), vectors=tuple(tuple(float((i+j)%5) for j in range(len(names))) for i in range(10)),hostnames=("test",)*10,window_starts=tuple(f"2026-10-03T10:{i:02d}:00+00:00" for i in range(10)),feature_schema_version=2)
    artifact=BehavioralAnomalyTrainer(n_estimators=5).train(dataset)
    return BehavioralAnomalyExplainer(artifact, baseline_stats={n:(10.0,1.0) for n in names})


@pytest.mark.parametrize('value,direction',[(2.0,'below'),(18.0,'above'),(10.0,'at')])
def test_reference_direction_is_preserved_without_changing_score(reference_explainer,value,direction):
    e=reference_explainer.explain_vector([value]*len(BehavioralWindow.FEATURE_NAMES_V2),score=-0.7,decision_margin=-0.1,is_anomalous=True)
    assert e.score==-0.7 and e.decision_margin==-0.1
    for factor in e.all_attributions:
        assert factor.to_dict()['direction']==direction
        assert f'is {direction} the reference' in factor.description
        assert factor.deviation_zscore==abs(value-10.0)
        assert 'elevated' not in factor.description


@pytest.mark.parametrize('name',['process_event_count','network_connection_count','max_cgroup_memory_used_ratio','kernel_event_count','auth_failure_count'])
def test_below_reference_values_do_not_trigger_spike_countermeasures(name):
    factor=FeatureAttribution(name,1.0,10.0,1.0,9.0,1.0,100.0,'Below reference')
    now=datetime.now(timezone.utc)
    explanation=WindowExplanation('test',now,now,True,-0.7,-0.1,'Test',(factor,),(factor,))
    recommendations=MitigationRecommender.recommend(explanation)
    assert all(not r.state_changing for r in recommendations)
    assert all(r.category=='system_information' for r in recommendations)
