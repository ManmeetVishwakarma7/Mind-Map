const test = require('node:test');
const assert = require('node:assert/strict');
const { classifyTopic, buildGuidance, scoreAnswers } = require('../src/engine');

test('a not-studied topic is never labelled as failed', () => {
  assert.equal(classifyTopic({ studied:false, attempts:0, accuracy:0 }), 'not_studied');
  assert.equal(buildGuidance([{ id:1, topic:'Stacks', studied:false, attempts:0, accuracy:0 }])[0].status, 'not_studied');
});

test('a topic with no assessment remains unassessed', () => {
  assert.equal(classifyTopic({ studied:true, attempts:0, accuracy:0 }), 'not_assessed');
});

test('topic thresholds use weighted assessment accuracy', () => {
  assert.equal(classifyTopic({ studied:true, attempts:2, accuracy:80 }), 'strong');
  assert.equal(classifyTopic({ studied:true, attempts:1, accuracy:50 }), 'moderate');
  assert.equal(classifyTopic({ studied:true, attempts:1, accuracy:49.9 }), 'needs_improvement');
});

test('scoreAnswers grades choice, multiple select and short answer', () => {
  const questions=[
    { id:1,type:'mcq',correct_answer:'B',marks:2 },
    { id:2,type:'multiple_select',correct_answer:'["A","C"]',marks:1 },
    { id:3,type:'short_answer',correct_answer:'Queue',marks:1 }
  ];
  const result=scoreAnswers(questions,{1:'B',2:['C','A'],3:' queue '});
  assert.equal(result.earned,4);
  assert.equal(result.possible,4);
  assert.equal(result.accuracy,100);
});
