import { CheckCircle2, RotateCcw, XCircle } from 'lucide-react'
import { useState } from 'react'
import type { QuizQuestion } from '../types'
import { btnGhost, btnPrimary, Card, CodeBlock, Rich } from './ui'

interface Props {
  questions: QuizQuestion[]
  best?: number
  onFinish: (score: number) => void
}

function shuffledOrder(length: number) {
  const order = Array.from({ length }, (_, i) => i)
  for (let i = length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1))
    ;[order[i], order[j]] = [order[j], order[i]]
  }
  return order
}

export function Quiz({ questions, best, onFinish }: Props) {
  // Ordre tiré à chaque tentative : la position de la bonne réponse ne s'apprend pas par cœur.
  const [orders, setOrders] = useState(() => questions.map((question) => shuffledOrder(question.options.length)))
  const [index, setIndex] = useState(0)
  const [choice, setChoice] = useState<number | null>(null)
  const [correct, setCorrect] = useState(0)
  const [done, setDone] = useState(false)
  const q = questions[index]

  const restart = () => {
    setOrders(questions.map((question) => shuffledOrder(question.options.length)))
    setIndex(0)
    setChoice(null)
    setCorrect(0)
    setDone(false)
  }

  const next = () => {
    if (index + 1 === questions.length) {
      setDone(true)
      onFinish(Math.round((correct / questions.length) * 100))
    } else {
      setIndex(index + 1)
      setChoice(null)
    }
  }

  if (done) {
    const score = Math.round((correct / questions.length) * 100)
    const passed = score >= 70
    return (
      <Card className="p-6 text-center">
        <p className={`text-4xl font-bold ${passed ? 'text-emerald' : 'text-amber'}`}>{score} %</p>
        <p className="mt-2">
          {correct} bonnes réponses sur {questions.length}. {passed ? 'Module validé.' : 'Il faut 70 % pour valider. Reprenez le cours sur les points manqués.'}
        </p>
        <button type="button" onClick={restart} className={`${btnGhost} mt-4`}>
          <RotateCcw size={15} /> Recommencer
        </button>
      </Card>
    )
  }

  const answered = choice !== null
  return (
    <Card className="p-4 sm:p-6">
      <div className="mb-3 flex items-center justify-between text-xs text-mute">
        <span>
          Question {index + 1} / {questions.length}
        </span>
        {best !== undefined && <span>Meilleur score : {best} %</span>}
      </div>
      <p className="font-medium text-white">
        <Rich text={q.q} />
      </p>
      {q.evidence && <CodeBlock code={q.evidence.code} lang={q.evidence.lang} title="Preuve à analyser" />}
      <div className="mt-4 space-y-2" role="group" aria-label="Réponses">
        {orders[index].map((i) => {
          const option = q.options[i]
          let cls = 'border-line hover:border-cyan'
          if (answered) {
            if (i === q.answer) cls = 'border-emerald bg-emerald/10'
            else if (i === choice) cls = 'border-crimson bg-crimson/10'
            else cls = 'border-line opacity-60'
          }
          return (
            <button
              key={i}
              type="button"
              disabled={answered}
              onClick={() => {
                setChoice(i)
                if (i === q.answer) setCorrect((c) => c + 1)
              }}
              className={`flex w-full items-start gap-2 rounded-md border p-3 text-left text-sm transition ${cls}`}
            >
              {answered && i === q.answer && <CheckCircle2 size={17} className="mt-0.5 shrink-0 text-emerald" aria-label="Bonne réponse" />}
              {answered && i === choice && i !== q.answer && <XCircle size={17} className="mt-0.5 shrink-0 text-crimson" aria-label="Votre réponse, incorrecte" />}
              <span>
                <Rich text={option} />
              </span>
            </button>
          )
        })}
      </div>
      {answered && (
        <div className="mt-4 rounded-md border border-line bg-raised p-3 text-sm" aria-live="polite">
          <p className="mb-1 font-semibold text-white">{choice === q.answer ? 'Exact.' : 'Pas tout à fait.'}</p>
          <Rich text={q.explain} />
          <div className="mt-3 text-right">
            <button type="button" onClick={next} className={btnPrimary}>
              {index + 1 === questions.length ? 'Voir le résultat' : 'Question suivante'}
            </button>
          </div>
        </div>
      )}
    </Card>
  )
}
