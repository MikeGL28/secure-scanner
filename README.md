# Secure Scanner

Статический анализатор кода для Python, который обнаруживает:
- SQL-инъекции через f-строки
- Опасные функции: eval, exec
- Небезопасную десериализацию: pickle.loads, yaml.load
- И другие уязвимости...

Результаты выводятся в удобочитаемом текстовом формате или в стандарте SARIF для интеграции в CI/CD (например, GitHub Actions).

## Использование

```bash
# Пример: анализ тестового файла с уязвимостями
python -m scanner --path ./tests/test_samples

# Пример: анализ всего проекта и вывод в SARIF (для GitHub Actions)
python -m scanner --path . --format sarif
```
## Интеграция с GitHub
Сканер автоматически запускается при пуше или создании Pull Request и отображает найденные уязвимости во вкладке Security → Code scanning alerts.