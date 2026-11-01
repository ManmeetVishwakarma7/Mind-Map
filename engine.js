const THRESHOLDS = { strong: 80, moderate: 50 };

function classifyTopic({ studied, attempts, accuracy }) {
  if (!studied) return 'not_studied';
  if (!attempts) return 'not_assessed';
  if (accuracy >= THRESHOLDS.strong) return 'strong';
  if (accuracy >= THRESHOLDS.moderate) return 'moderate';
  return 'needs_improvement';
}

function buildGuidance(rows) {
  return rows.map((topic) => {
    const status = classifyTopic(topic);
    const item = { ...topic, status };
    if (status === 'not_studied') {
      item.recommendation = 'Study this syllabus topic, then update your coverage to studied before attempting questions.';
      item.reason = 'You marked this topic as not studied. It was excluded from your scores.';
    } else if (status === 'not_assessed') {
      item.recommendation = 'Attempt a short assessment to establish a baseline.';
      item.reason = 'There is no assessment history for this studied topic yet.';
    } else if (status === 'needs_improvement') {
      item.recommendation = 'Review the topic notes, then practise a fresh set of questions.';
      item.reason = `Your assessed accuracy is ${Math.round(topic.accuracy)}%.`;
    } else if (status === 'moderate') {
      item.recommendation = 'Revisit the concepts you missed and reassess to strengthen recall.';
      item.reason = `Your assessed accuracy is ${Math.round(topic.accuracy)}%.`;
    } else {
      item.recommendation = 'Continue to the next topic and revisit this one during spaced review.';
      item.reason = `Your assessed accuracy is ${Math.round(topic.accuracy)}%.`;
    }
    return item;
  });
}

function scoreAnswers(questions, answers) {
  let earned = 0;
  let possible = 0;
  let correctCount = 0;
  const graded = questions.map((question) => {
    const answer = answers[question.id] ?? null;
    const expected = question.correct_answer;
    let correct = false;
    if (question.type === 'multiple_select') {
      const actualSet = [...new Set(Array.isArray(answer) ? answer.map(String) : [])].sort();
      const expectedSet = [...new Set(JSON.parse(expected).map(String))].sort();
      correct = actualSet.length === expectedSet.length && actualSet.every((value, i) => value === expectedSet[i]);
    } else if (question.type === 'short_answer') {
      correct = String(answer ?? '').trim().toLowerCase() === String(expected).trim().toLowerCase();
    } else {
      correct = String(answer ?? '') === String(expected);
    }
    possible += question.marks;
    if (correct) { earned += question.marks; correctCount += 1; }
    return { question_id: question.id, answer, correct, earned: correct ? question.marks : 0 };
  });
  return { graded, earned, possible, correctCount, accuracy: possible ? earned / possible * 100 : 0 };
}

module.exports = { THRESHOLDS, classifyTopic, buildGuidance, scoreAnswers };
