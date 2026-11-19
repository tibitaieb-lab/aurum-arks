"""Golden evaluation independent of query ranking; immutable explicit targets."""
from collections import Counter

def evaluate_test(test, found):
    def target(hit):
        return (hit['source_id']==test.get('expected_source_id')
                and (not test.get('expected_evidence_id') or any(s['evidence_id']==test['expected_evidence_id'] for s in hit['evidence_spans']))
                and (not test.get('expected_page') or any(p['physical_page']==test['expected_page'] and (not test.get('expected_evidence_id') or p['evidence_id']==test['expected_evidence_id']) for p in hit['page_refs'])))
    def filters_ok(hit):
        for key,value in test.get('filters',{}).items():
            actual=hit.get(key,hit['metadata'].get(key));actual=actual if isinstance(actual,list) else [actual]
            if value not in actual:return False
        return True
    ids=[h['source_id'] for h in found];expected=set(test.get('expected_source_ids',[]))
    positive=bool(test.get('expected_source_id')) and not test.get('expected_empty',False) and test['query_type']!='NEGATIVE'
    rank=next((i+1 for i,h in enumerate(found) if target(h)),None)
    return {'id':test['id'],'query_type':test['query_type'],'positive_target':positive,'expected_empty':test.get('expected_empty',False),'rank':rank,'source_rank':next((i+1 for i,k in enumerate(ids) if k==test.get('expected_source_id')),None),'filters_ok':all(filters_ok(h) for h in found),'negative_ok':not found if test.get('expected_empty') else all(h['provenance']=='VERIFIED' for h in found),'provenance_valid':all(h['provenance']=='VERIFIED' for h in found),'sources_found':ids,'distinct_expected_sources_found':len(set(ids)&expected),'expected_sources_count':len(expected),'source_concentration':max(Counter(ids).values(),default=0)/len(ids) if ids else 0,'repeated_evidence_slots':len(found)-len({s['evidence_id'] for h in found for s in h['evidence_spans']})}

def summarize(rows):
    scored=[r for r in rows if r['positive_target']]
    def rate(group,predicate):return sum(bool(predicate(x)) for x in group)/len(group) if group else None
    metrics={'positive_denominator':len(scored),'Hit@5':rate(scored,lambda x:x['rank'] is not None and x['rank']<=5),'Hit@10':rate(scored,lambda x:x['rank'] is not None and x['rank']<=10),'MRR':sum(1/x['rank'] if x['rank'] else 0 for x in scored)/len(scored) if scored else None,'SOURCE_HIT@10':rate(scored,lambda x:x['source_rank'] is not None and x['source_rank']<=10)}
    for kind,k in [('EXACT',5),('PARAPHRASE',10),('FILTER',10)]:
        group=[r for r in scored if r['query_type']==kind];metrics[kind+'_DENOMINATOR']=len(group);metrics[kind+'_HIT@'+str(k)]=rate(group,lambda x:x['rank'] is not None and x['rank']<=k)
    metrics.update(EXACT_TERM_HIT_AT_5=metrics['EXACT_HIT@5'],FILTERED_QUERY_HIT=metrics['FILTER_HIT@10'],PROVENANCE_VALID=all(x['provenance_valid'] for x in rows),FILTER_TESTS=all(x['filters_ok'] for x in rows),NEGATIVE_TESTS=all(x['negative_ok'] for x in rows))
    multi=[r for r in rows if r['query_type']=='MULTI_SOURCE']
    metrics['MULTI_SOURCE']=[{'id':r['id'],'found':r['distinct_expected_sources_found'],'expected':r['expected_sources_count'],'coverage':r['distinct_expected_sources_found']/r['expected_sources_count'],'at_least_two':r['distinct_expected_sources_found']>=2} for r in multi]
    return metrics

def accepted(m):
    return m['EXACT_HIT@5']==1 and m['PARAPHRASE_HIT@10']>=.9 and m['FILTER_HIT@10']==1 and m['PROVENANCE_VALID'] and m['FILTER_TESTS'] and m['NEGATIVE_TESTS']
